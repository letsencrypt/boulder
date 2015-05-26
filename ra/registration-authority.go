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

	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
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

func (ra *RegistrationAuthorityImpl) NewRegistration(init core.Registration, key jose.JsonWebKey) (reg core.Registration, err error) {
	reg = core.Registration{
		Key:           key,
		RecoveryToken: core.NewToken(),
	}
	reg.MergeUpdate(init)

	// Store the authorization object, then return it
	reg, err = ra.SA.NewRegistration(reg)
	return
}

func (ra *RegistrationAuthorityImpl) NewAuthorization(request core.Authorization, regID int64) (authz core.Authorization, err error) {
	if regID <= 0 {
		err = fmt.Errorf("Invalid registration ID")
		return authz, err
	}

	identifier := request.Identifier

	// Check that the identifier is present and appropriate
	if err = ra.PA.WillingToIssue(identifier); err != nil {
		return authz, err
	}

	// Create validations
	// TODO: Assign URLs
	challenges, combinations := ra.PA.ChallengesFor(identifier)
	authID, err := ra.SA.NewPendingAuthorization()
	if err != nil {
		return authz, err
	}
	for i := range challenges {
		// Ignoring these errors because we construct the URLs to be correct
		challengeURI, _ := url.Parse(ra.AuthzBase + authID + "?challenge=" + strconv.Itoa(i))
		challenges[i].URI = core.AcmeURL(*challengeURI)

		if !challenges[i].IsSane(false) {
			err = fmt.Errorf("Challenge didn't pass sanity check: %+v", challenges[i])
			return authz, err
		}
	}

	// Create a new authorization object
	authz = core.Authorization{
		ID:             authID,
		Identifier:     identifier,
		RegistrationID: regID,
		Status:         core.StatusPending,
		Challenges:     challenges,
		Combinations:   combinations,
	}

	// Store the authorization object, then return it
	err = ra.SA.UpdatePendingAuthorization(authz)
	return authz, err
}

func (ra *RegistrationAuthorityImpl) NewCertificate(req core.CertificateRequest, regID int64) (core.Certificate, error) {
	emptyCert := core.Certificate{}
	var err error
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
		err = fmt.Errorf("Invalid registration ID")
		return emptyCert, err
	}

	// Verify the CSR
	// TODO: Verify that other aspects of the CSR are appropriate
	csr := req.CSR
	if err = core.VerifyCSR(csr); err != nil {
		logEvent.Error = err.Error()
		err = core.UnauthorizedError("Invalid signature on CSR")
		return emptyCert, err
	}

	logEvent.CommonName = csr.Subject.CommonName
	logEvent.Names = csr.DNSNames

	csrPreviousDenied, err := ra.SA.AlreadyDeniedCSR(append(csr.DNSNames, csr.Subject.CommonName))
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

	// Validate that authorization key is authorized for all domains
	names := csr.DNSNames
	if len(csr.Subject.CommonName) > 0 {
		names = append(names, csr.Subject.CommonName)
	}

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
	var cert core.Certificate
	if cert, err = ra.CA.IssueCertificate(*csr, regID); err != nil {
		logEvent.Error = err.Error()
		return emptyCert, nil
	}

	cert.ParsedCertificate, err = x509.ParseCertificate([]byte(cert.DER))

	logEvent.SerialNumber = cert.ParsedCertificate.SerialNumber
	logEvent.CommonName = cert.ParsedCertificate.Subject.CommonName
	logEvent.NotBefore = cert.ParsedCertificate.NotBefore
	logEvent.NotAfter = cert.ParsedCertificate.NotAfter
	logEvent.ResponseTime = time.Now()

	logEventResult = "successful"
	return cert, nil
}

func (ra *RegistrationAuthorityImpl) UpdateRegistration(base core.Registration, update core.Registration) (reg core.Registration, err error) {
	base.MergeUpdate(update)
	reg = base
	err = ra.SA.UpdateRegistration(base)
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
		return
	}

	// Dispatch to the VA for service
	ra.VA.UpdateValidations(authz, challengeIndex)

	return
}

func (ra *RegistrationAuthorityImpl) RevokeCertificate(cert x509.Certificate) error {
	serialString := core.SerialToString(cert.SerialNumber)
	err := ra.CA.RevokeCertificate(serialString)

	// AUDIT[ Revocation Requests ] 4e85d791-09c0-4ab3-a837-d3d67e945134
	if err != nil {
		ra.log.Audit(fmt.Sprintf("Revocation error - %s - %s", serialString, err))
	} else {
		ra.log.Audit(fmt.Sprintf("Revocation - %s", serialString))
	}

	return err
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
