// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ra

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/policy"
)

// All of the fields in RegistrationAuthorityImpl need to be
// populated, or there is a risk of panic.
type RegistrationAuthorityImpl struct {
	CA  core.CertificateAuthority
	VA  core.ValidationAuthority
	SA  core.StorageAuthority
	PA  core.PolicyAuthority
	log *blog.AuditLogger

	AuthzBase string
}

func NewRegistrationAuthorityImpl() RegistrationAuthorityImpl {
	logger := blog.GetAuditLogger()
	logger.Notice("Registration Authority Starting")

	ra := RegistrationAuthorityImpl{log: logger}
	ra.PA = policy.NewPolicyAuthorityImpl()
	return ra
}

var allButLastPathSegment = regexp.MustCompile("^.*/")

func lastPathSegment(url core.AcmeURL) string {
	return allButLastPathSegment.ReplaceAllString(url.Path, "")
}

type certificateRequestEvent struct {
	ID                  string    `json:",omitempty"`
	Requester           int64     `json:",omitempty"`
	SerialNumber        *big.Int  `json:",omitempty"`
	RequestMethod       string    `json:",omitempty"`
	VerificationMethods []string  `json:",omitempty"`
	VerifiedFields      []string  `json:",omitempty"`
	CommonName          string    `json:",omitempty"`
	Names               []string  `json:",omitempty"`
	NotBefore           time.Time `json:",omitempty"`
	NotAfter            time.Time `json:",omitempty"`
	RequestTime         time.Time `json:",omitempty"`
	ResponseTime        time.Time `json:",omitempty"`
	Error               string    `json:",omitempty"`
}

func (ra *RegistrationAuthorityImpl) NewRegistration(init core.Registration) (reg core.Registration, err error) {
	if !core.GoodKey(init.Key.Key) {
		return core.Registration{}, core.UnauthorizedError("Invalid public key.")
	}
	reg = core.Registration{
		RecoveryToken: core.NewToken(),
		Key:           init.Key,
	}
	reg.MergeUpdate(init)

	// Store the authorization object, then return it
	reg, err = ra.SA.NewRegistration(reg)
	if err != nil {
		err = core.InternalServerError(err.Error())
	}
	return
}

func (ra *RegistrationAuthorityImpl) NewAuthorization(request core.Authorization, regID int64) (authz core.Authorization, err error) {
	if regID <= 0 {
		err = core.InternalServerError("Invalid registration ID")
		return authz, err
	}

	identifier := request.Identifier

	// Check that the identifier is present and appropriate
	if err = ra.PA.WillingToIssue(identifier); err != nil {
		err = core.UnauthorizedError(err.Error())
		return authz, err
	}

	// Create validations, but we have to update them with URIs later
	challenges, combinations := ra.PA.ChallengesFor(identifier)

	// Partially-filled object
	authz = core.Authorization{
		Identifier:     identifier,
		RegistrationID: regID,
		Status:         core.StatusPending,
		Combinations:   combinations,
	}

	// Get a pending Auth first so we can get our ID back, then update with challenges
	authz, err = ra.SA.NewPendingAuthorization(authz)
	if err != nil {
		err = core.InternalServerError(err.Error())
		return authz, err
	}

	// Construct all the challenge URIs
	for i := range challenges {
		// Ignoring these errors because we construct the URLs to be correct
		challengeURI, _ := url.Parse(ra.AuthzBase + authz.ID + "?challenge=" + strconv.Itoa(i))
		challenges[i].URI = core.AcmeURL(*challengeURI)

		if !challenges[i].IsSane(false) {
			err = core.InternalServerError(fmt.Sprintf("Challenge didn't pass sanity check: %+v", challenges[i]))
			return authz, err
		}
	}

	// Update object
	authz.Challenges = challenges

	// Store the authorization object, then return it
	err = ra.SA.UpdatePendingAuthorization(authz)
	if err != nil {
		err = core.InternalServerError(err.Error())
	}
	return authz, err
}

func (ra *RegistrationAuthorityImpl) NewCertificate(req core.CertificateRequest, regID int64) (cert core.Certificate, err error) {
	emptyCert := core.Certificate{}
	var logEventResult string

	// Assume the worst
	logEventResult = "error"

	// Construct the log event
	logEvent := certificateRequestEvent{
		ID:            core.NewToken(),
		Requester:     regID,
		RequestMethod: "online",
		RequestTime:   time.Now(),
	}

	// No matter what, log the request
	defer func() {
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ra.log.AuditObject(fmt.Sprintf("Certificate request - %s", logEventResult), logEvent)
	}()

	if regID <= 0 {
		err = core.InternalServerError("Invalid registration ID")
		return emptyCert, err
	}

	// Verify the CSR
	csr := req.CSR
	if err = core.VerifyCSR(csr); err != nil {
		logEvent.Error = err.Error()
		err = core.UnauthorizedError("Invalid signature on CSR")
		return emptyCert, err
	}

	logEvent.CommonName = csr.Subject.CommonName
	logEvent.Names = csr.DNSNames

	// Validate that authorization key is authorized for all domains
	names := make([]string, len(csr.DNSNames))
	copy(names, csr.DNSNames)
	if len(csr.Subject.CommonName) > 0 {
		names = append(names, csr.Subject.CommonName)
	}

	if len(names) == 0 {
		err = core.UnauthorizedError("CSR has no names in it")
		logEvent.Error = err.Error()
		return emptyCert, err
	}

	csrPreviousDenied, err := ra.SA.AlreadyDeniedCSR(names)
	if err != nil {
		logEvent.Error = err.Error()
		return emptyCert, err
	}
	if csrPreviousDenied {
		err = core.UnauthorizedError("CSR has already been revoked/denied")
		logEvent.Error = err.Error()
		return emptyCert, err
	}

	registration, err := ra.SA.GetRegistration(regID)
	if err != nil {
		err = core.InternalServerError(err.Error())
		logEvent.Error = err.Error()
		return emptyCert, err
	}

	if core.KeyDigestEquals(csr.PublicKey, registration.Key) {
		err = core.MalformedRequestError("Certificate public key must be different than account key")
		return emptyCert, err
	}

	// Gather authorized domains from the referenced authorizations
	authorizedDomains := map[string]bool{}
	verificationMethodSet := map[string]bool{}
	earliestExpiry := time.Date(2100, 01, 01, 0, 0, 0, 0, time.UTC)
	now := time.Now()
	for _, url := range req.Authorizations {
		id := lastPathSegment(url)
		authz, err := ra.SA.GetAuthorization(id)
		if err != nil || // Couldn't find authorization
			authz.RegistrationID != registration.ID ||
			authz.Status != core.StatusValid || // Not finalized or not successful
			authz.Expires.Before(now) || // Expired
			authz.Identifier.Type != core.IdentifierDNS {
			// XXX: It may be good to fail here instead of ignoring invalid authorizations.
			//      However, it seems like this treatment is more in the spirit of Postel's
			//      law, and it hides information from attackers.
			continue
		}

		if authz.Expires.Before(earliestExpiry) {
			earliestExpiry = authz.Expires
		}

		for _, challenge := range authz.Challenges {
			if challenge.Status == core.StatusValid {
				verificationMethodSet[challenge.Type] = true
			}
		}

		authorizedDomains[authz.Identifier.Value] = true
	}
	verificationMethods := []string{}
	for method, _ := range verificationMethodSet {
		verificationMethods = append(verificationMethods, method)
	}
	logEvent.VerificationMethods = verificationMethods

	// Validate all domains
	for _, name := range names {
		if !authorizedDomains[name] {
			err = core.UnauthorizedError(fmt.Sprintf("Key not authorized for name %s", name))
			logEvent.Error = err.Error()
			return emptyCert, err
		}
	}

	// Mark that we verified the CN and SANs
	logEvent.VerifiedFields = []string{"subject.commonName", "subjectAltName"}

	// Create the certificate and log the result
	if cert, err = ra.CA.IssueCertificate(*csr, regID, earliestExpiry); err != nil {
		err = core.InternalServerError(err.Error())
		logEvent.Error = err.Error()
		return emptyCert, err
	}

	parsedCertificate, err := x509.ParseCertificate([]byte(cert.DER))
	if err != nil {
		err = core.InternalServerError(err.Error())
		logEvent.Error = err.Error()
		return emptyCert, err
	}

	logEvent.SerialNumber = parsedCertificate.SerialNumber
	logEvent.CommonName = parsedCertificate.Subject.CommonName
	logEvent.NotBefore = parsedCertificate.NotBefore
	logEvent.NotAfter = parsedCertificate.NotAfter
	logEvent.ResponseTime = time.Now()

	logEventResult = "successful"
	return cert, nil
}

func (ra *RegistrationAuthorityImpl) UpdateRegistration(base core.Registration, update core.Registration) (reg core.Registration, err error) {
	base.MergeUpdate(update)
	reg = base
	err = ra.SA.UpdateRegistration(base)
	if err != nil {
		err = core.InternalServerError(err.Error())
	}
	return
}

func (ra *RegistrationAuthorityImpl) UpdateAuthorization(base core.Authorization, challengeIndex int, response core.Challenge) (authz core.Authorization, err error) {
	// Copy information over that the client is allowed to supply
	authz = base
	if challengeIndex >= len(authz.Challenges) {
		err = core.MalformedRequestError("Invalid challenge index")
		return
	}
	authz.Challenges[challengeIndex] = authz.Challenges[challengeIndex].MergeResponse(response)

	// Store the updated version
	if err = ra.SA.UpdatePendingAuthorization(authz); err != nil {
		err = core.InternalServerError(err.Error())
		return
	}

	// Dispatch to the VA for service
	ra.VA.UpdateValidations(authz, challengeIndex)

	return
}

func (ra *RegistrationAuthorityImpl) RevokeCertificate(cert x509.Certificate) (err error) {
	serialString := core.SerialToString(cert.SerialNumber)
	err = ra.CA.RevokeCertificate(serialString, 0)

	// AUDIT[ Revocation Requests ] 4e85d791-09c0-4ab3-a837-d3d67e945134
	if err != nil {
		ra.log.Audit(fmt.Sprintf("Revocation error - %s - %s", serialString, err))
		err = core.InternalServerError(err.Error())
		return
	}

	ra.log.Audit(fmt.Sprintf("Revocation - %s", serialString))
	return
}

func (ra *RegistrationAuthorityImpl) OnValidationUpdate(authz core.Authorization) error {
	// Check to see whether the updated validations are sufficient
	// Current policy is to accept if any validation succeeded
	for _, val := range authz.Challenges {
		if val.Status == core.StatusValid {
			authz.Status = core.StatusValid
			break
		}
	}

	// If no validation succeeded, then the authorization is invalid
	// NOTE: This only works because we only ever do one validation
	if authz.Status != core.StatusValid {
		authz.Status = core.StatusInvalid
	} else {
		// TODO: Enable configuration of expiry time
		authz.Expires = time.Now().Add(365 * 24 * time.Hour)
	}

	// Finalize the authorization (error ignored)
	return ra.SA.FinalizeAuthorization(authz)
}
