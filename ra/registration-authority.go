// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ra

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/mail"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

// RegistrationAuthorityImpl defines an RA.
//
// NOTE: All of the fields in RegistrationAuthorityImpl need to be
// populated, or there is a risk of panic.
type RegistrationAuthorityImpl struct {
	CA          core.CertificateAuthority
	VA          core.ValidationAuthority
	SA          core.StorageAuthority
	PA          core.PolicyAuthority
	DNSResolver core.DNSResolver
	clk         clock.Clock
	log         *blog.AuditLogger
}

// NewRegistrationAuthorityImpl constructs a new RA object.
func NewRegistrationAuthorityImpl(clk clock.Clock, logger *blog.AuditLogger) RegistrationAuthorityImpl {
	ra := RegistrationAuthorityImpl{clk: clk, log: logger}
	return ra
}

func validateEmail(address string, resolver core.DNSResolver) (err error) {
	_, err = mail.ParseAddress(address)
	if err != nil {
		err = core.MalformedRequestError(fmt.Sprintf("%s is not a valid e-mail address", address))
		return
	}
	splitEmail := strings.SplitN(address, "@", -1)
	domain := strings.ToLower(splitEmail[len(splitEmail)-1])
	var mx []string
	mx, _, err = resolver.LookupMX(domain)
	if err != nil || len(mx) == 0 {
		err = core.MalformedRequestError(fmt.Sprintf("No MX record for domain %s", domain))
		return
	}
	return
}

func validateContacts(contacts []*core.AcmeURL, resolver core.DNSResolver) (err error) {
	for _, contact := range contacts {
		switch contact.Scheme {
		case "tel":
			continue
		case "mailto":
			err = validateEmail(contact.Opaque, resolver)
			if err != nil {
				return
			}
		default:
			err = core.MalformedRequestError(fmt.Sprintf("Contact method %s is not supported", contact.Scheme))
			return
		}
	}

	return
}

type certificateRequestEvent struct {
	ID                  string    `json:",omitempty"`
	Requester           int64     `json:",omitempty"`
	SerialNumber        string    `json:",omitempty"`
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

// NewRegistration constructs a new Registration from a request.
func (ra *RegistrationAuthorityImpl) NewRegistration(init core.Registration) (reg core.Registration, err error) {
	if err = core.GoodKey(init.Key.Key); err != nil {
		return core.Registration{}, core.MalformedRequestError(fmt.Sprintf("Invalid public key: %s", err.Error()))
	}
	reg = core.Registration{
		Key: init.Key,
	}
	reg.MergeUpdate(init)

	err = validateContacts(reg.Contact, ra.DNSResolver)
	if err != nil {
		return
	}

	// Store the authorization object, then return it
	reg, err = ra.SA.NewRegistration(reg)
	if err != nil {
		// InternalServerError since the user-data was validated before being
		// passed to the SA.
		err = core.InternalServerError(err.Error())
	}

	return
}

// NewAuthorization constuct a new Authz from a request.
func (ra *RegistrationAuthorityImpl) NewAuthorization(request core.Authorization, regID int64) (authz core.Authorization, err error) {
	reg, err := ra.SA.GetRegistration(regID)
	if err != nil {
		err = core.MalformedRequestError(fmt.Sprintf("Invalid registration ID: %d", regID))
		return authz, err
	}

	identifier := request.Identifier

	// Check that the identifier is present and appropriate
	if err = ra.PA.WillingToIssue(identifier); err != nil {
		err = core.UnauthorizedError(err.Error())
		return authz, err
	}

	// Check CAA records for the requested identifier
	present, valid, err := ra.VA.CheckCAARecords(identifier)
	if err != nil {
		return authz, err
	}
	// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
	ra.log.Audit(fmt.Sprintf("Checked CAA records for %s, registration ID %d [Present: %t, Valid for issuance: %t]", identifier.Value, regID, present, valid))
	if !valid {
		err = errors.New("CAA check for identifier failed")
		return authz, err
	}

	// Create validations, but we have to update them with URIs later
	challenges, combinations := ra.PA.ChallengesFor(identifier)

	for i, _ := range challenges {
		// Add the account key used to generate the challenge
		challenges[i].AccountKey = &reg.Key
	}

	// Partially-filled object
	authz = core.Authorization{
		Identifier:     identifier,
		RegistrationID: regID,
		Status:         core.StatusPending,
		Combinations:   combinations,
		Challenges:     challenges,
	}

	// Get a pending Auth first so we can get our ID back, then update with challenges
	authz, err = ra.SA.NewPendingAuthorization(authz)
	if err != nil {
		// InternalServerError since the user-data was validated before being
		// passed to the SA.
		err = core.InternalServerError(fmt.Sprintf("Invalid authorization request: %s", err))
		return core.Authorization{}, err
	}

	// Check each challenge for sanity.
	for _, challenge := range authz.Challenges {
		if !challenge.IsSane(false) {
			// InternalServerError because we generated these challenges, they should
			// be OK.
			err = core.InternalServerError(fmt.Sprintf("Challenge didn't pass sanity check: %+v", challenge))
			return core.Authorization{}, err
		}
	}

	return authz, err
}

// MatchesCSR tests the contents of a generated certificate to make sure
// that the PublicKey, CommonName, and DNSNames match those provided in
// the CSR that was used to generate the certificate. It also checks the
// following fields for:
//		* notAfter is after earliestExpiry
//		* notBefore is not more than 24 hours ago
//		* BasicConstraintsValid is true
//		* IsCA is false
//		* ExtKeyUsage only contains ExtKeyUsageServerAuth & ExtKeyUsageClientAuth
//		* Subject only contains CommonName & Names
func (ra *RegistrationAuthorityImpl) MatchesCSR(
	cert core.Certificate,
	csr *x509.CertificateRequest,
	earliestExpiry time.Time) (err error) {
	parsedCertificate, err := x509.ParseCertificate([]byte(cert.DER))
	if err != nil {
		return
	}

	// Check issued certificate matches what was expected from the CSR
	hostNames := make([]string, len(csr.DNSNames))
	copy(hostNames, csr.DNSNames)
	if len(csr.Subject.CommonName) > 0 {
		hostNames = append(hostNames, csr.Subject.CommonName)
	}
	hostNames = core.UniqueNames(hostNames)

	if !core.KeyDigestEquals(parsedCertificate.PublicKey, csr.PublicKey) {
		err = core.InternalServerError("Generated certificate public key doesn't match CSR public key")
		return
	}
	if len(csr.Subject.CommonName) > 0 && parsedCertificate.Subject.CommonName != csr.Subject.CommonName {
		err = core.InternalServerError("Generated certificate CommonName doesn't match CSR CommonName")
		return
	}
	// Sort both slices of names before comparison.
	parsedNames := parsedCertificate.DNSNames
	sort.Strings(parsedNames)
	sort.Strings(hostNames)
	if !reflect.DeepEqual(parsedNames, hostNames) {
		err = core.InternalServerError("Generated certificate DNSNames don't match CSR DNSNames")
		return
	}
	if !reflect.DeepEqual(parsedCertificate.IPAddresses, csr.IPAddresses) {
		err = core.InternalServerError("Generated certificate IPAddresses don't match CSR IPAddresses")
		return
	}
	if !reflect.DeepEqual(parsedCertificate.EmailAddresses, csr.EmailAddresses) {
		err = core.InternalServerError("Generated certificate EmailAddresses don't match CSR EmailAddresses")
		return
	}
	if len(parsedCertificate.Subject.Country) > 0 || len(parsedCertificate.Subject.Organization) > 0 ||
		len(parsedCertificate.Subject.OrganizationalUnit) > 0 || len(parsedCertificate.Subject.Locality) > 0 ||
		len(parsedCertificate.Subject.Province) > 0 || len(parsedCertificate.Subject.StreetAddress) > 0 ||
		len(parsedCertificate.Subject.PostalCode) > 0 || len(parsedCertificate.Subject.SerialNumber) > 0 {
		err = core.InternalServerError("Generated certificate Subject contains fields other than CommonName or Names")
		return
	}
	if parsedCertificate.NotAfter.After(earliestExpiry) {
		err = core.InternalServerError("Generated certificate expires before earliest expiration")
		return
	}
	now := ra.clk.Now()
	if now.Sub(parsedCertificate.NotBefore) > time.Hour*24 {
		err = core.InternalServerError(fmt.Sprintf("Generated certificate is back dated %s", now.Sub(parsedCertificate.NotBefore)))
		return
	}
	if !parsedCertificate.BasicConstraintsValid {
		err = core.InternalServerError("Generated certificate doesn't have basic constraints set")
		return
	}
	if parsedCertificate.IsCA {
		err = core.InternalServerError("Generated certificate can sign other certificates")
		return
	}
	if !reflect.DeepEqual(parsedCertificate.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) {
		err = core.InternalServerError("Generated certificate doesn't have correct key usage extensions")
		return
	}

	return
}

// NewCertificate requests the issuance of a certificate.
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
		RequestTime:   ra.clk.Now(),
	}

	// No matter what, log the request
	defer func() {
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ra.log.AuditObject(fmt.Sprintf("Certificate request - %s", logEventResult), logEvent)
	}()

	if regID <= 0 {
		err = core.MalformedRequestError(fmt.Sprintf("Invalid registration ID: %d", regID))
		return emptyCert, err
	}

	registration, err := ra.SA.GetRegistration(regID)
	if err != nil {
		logEvent.Error = err.Error()
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

	if core.KeyDigestEquals(csr.PublicKey, registration.Key) {
		err = core.MalformedRequestError("Certificate public key must be different than account key")
		return emptyCert, err
	}

	// Check that each requested name has a valid authorization
	now := ra.clk.Now()
	earliestExpiry := time.Date(2100, 01, 01, 0, 0, 0, 0, time.UTC)
	for _, name := range names {
		authz, err := ra.SA.GetLatestValidAuthorization(registration.ID, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: name})
		if err != nil || authz.Expires.Before(now) {
			// unable to find a valid authorization or authz is expired
			err = core.UnauthorizedError(fmt.Sprintf("Key not authorized for name %s", name))
			logEvent.Error = err.Error()
			return emptyCert, err
		}

		if authz.Expires.Before(earliestExpiry) {
			earliestExpiry = *authz.Expires
		}
	}

	// Mark that we verified the CN and SANs
	logEvent.VerifiedFields = []string{"subject.commonName", "subjectAltName"}

	// Create the certificate and log the result
	if cert, err = ra.CA.IssueCertificate(*csr, regID, earliestExpiry); err != nil {
		// While this could be InternalServerError for certain conditions, most
		// of the failure reasons (such as GoodKey failing) are caused by malformed
		// requests.
		logEvent.Error = err.Error()
		err = core.MalformedRequestError("Certificate request was invalid")
		return emptyCert, err
	}

	err = ra.MatchesCSR(cert, csr, earliestExpiry)
	if err != nil {
		logEvent.Error = err.Error()
		return emptyCert, err
	}

	parsedCertificate, err := x509.ParseCertificate([]byte(cert.DER))
	if err != nil {
		// InternalServerError because the certificate from the CA should be
		// parseable.
		err = core.InternalServerError(err.Error())
		logEvent.Error = err.Error()
		return emptyCert, err
	}

	logEvent.SerialNumber = core.SerialToString(parsedCertificate.SerialNumber)
	logEvent.CommonName = parsedCertificate.Subject.CommonName
	logEvent.NotBefore = parsedCertificate.NotBefore
	logEvent.NotAfter = parsedCertificate.NotAfter
	logEvent.ResponseTime = ra.clk.Now()

	logEventResult = "successful"
	return cert, nil
}

// UpdateRegistration updates an existing Registration with new values.
func (ra *RegistrationAuthorityImpl) UpdateRegistration(base core.Registration, update core.Registration) (reg core.Registration, err error) {
	base.MergeUpdate(update)

	err = validateContacts(base.Contact, ra.DNSResolver)
	if err != nil {
		return
	}

	reg = base
	err = ra.SA.UpdateRegistration(base)
	if err != nil {
		// InternalServerError since the user-data was validated before being
		// passed to the SA.
		err = core.InternalServerError(fmt.Sprintf("Could not update registration: %s", err))
	}
	return
}

// UpdateAuthorization updates an authorization with new values.
func (ra *RegistrationAuthorityImpl) UpdateAuthorization(base core.Authorization, challengeIndex int, response core.Challenge) (authz core.Authorization, err error) {
	// Copy information over that the client is allowed to supply
	authz = base
	if challengeIndex >= len(authz.Challenges) {
		err = core.MalformedRequestError(fmt.Sprintf("Invalid challenge index: %d", challengeIndex))
		return
	}
	authz.Challenges[challengeIndex] = authz.Challenges[challengeIndex].MergeResponse(response)

	// Store the updated version
	if err = ra.SA.UpdatePendingAuthorization(authz); err != nil {
		// This can pretty much only happen when the client corrupts the Challenge
		// data.
		err = core.MalformedRequestError("Challenge data was corrupted")
		return
	}

	// Look up the account key for this authorization
	reg, err := ra.SA.GetRegistration(authz.RegistrationID)
	if err != nil {
		err = core.InternalServerError(err.Error())
		return
	}

	// Reject the update if the challenge in question was created
	// with a different account key
	if !core.KeyDigestEquals(reg.Key, authz.Challenges[challengeIndex].AccountKey) {
		err = core.UnauthorizedError("Challenge cannot be updated with a different key")
		return
	}

	// Dispatch to the VA for service
	ra.VA.UpdateValidations(authz, challengeIndex)

	return
}

func revokeEvent(state, serial, cn string, names []string, revocationCode core.RevocationCode) string {
	return fmt.Sprintf(
		"Revocation - State: %s, Serial: %s, CN: %s, DNS Names: %s, Reason: %s",
		state,
		serial,
		cn,
		names,
		core.RevocationReasons[revocationCode],
	)
}

// RevokeCertificateWithReg terminates trust in the certificate provided.
func (ra *RegistrationAuthorityImpl) RevokeCertificateWithReg(cert x509.Certificate, revocationCode core.RevocationCode, regID int64) (err error) {
	serialString := core.SerialToString(cert.SerialNumber)
	err = ra.CA.RevokeCertificate(serialString, revocationCode)

	state := "Failure"
	defer func() {
		// AUDIT[ Revocation Requests ] 4e85d791-09c0-4ab3-a837-d3d67e945134
		// Needed:
		//   Serial
		//   CN
		//   DNS names
		//   Revocation reason
		//   Registration ID of requester
		//   Error (if there was one)
		ra.log.Audit(fmt.Sprintf(
			"%s, Request by registration ID: %d",
			revokeEvent(state, serialString, cert.Subject.CommonName, cert.DNSNames, revocationCode),
			regID,
		))
	}()

	if err != nil {
		state = fmt.Sprintf("Failure -- %s", err)
		return err
	}

	state = "Success"
	return nil
}

// AdministrativelyRevokeCertificate terminates trust in the certificate provided and
// does not require the registration ID of the requester since this method is only
// called from the admin-revoker tool.
func (ra *RegistrationAuthorityImpl) AdministrativelyRevokeCertificate(cert x509.Certificate, revocationCode core.RevocationCode, user string) error {
	serialString := core.SerialToString(cert.SerialNumber)
	err := ra.CA.RevokeCertificate(serialString, revocationCode)

	state := "Failure"
	defer func() {
		// AUDIT[ Revocation Requests ] 4e85d791-09c0-4ab3-a837-d3d67e945134
		// Needed:
		//   Serial
		//   CN
		//   DNS names
		//   Revocation reason
		//   Name of admin-revoker user
		//   Error (if there was one)
		ra.log.Audit(fmt.Sprintf(
			"%s, admin-revoker user: %s",
			revokeEvent(state, serialString, cert.Subject.CommonName, cert.DNSNames, revocationCode),
			user,
		))
	}()

	if err != nil {
		state = fmt.Sprintf("Failure -- %s", err)
		return err
	}

	state = "Success"
	return nil
}

// OnValidationUpdate is called when a given Authorization is updated by the VA.
func (ra *RegistrationAuthorityImpl) OnValidationUpdate(authz core.Authorization) error {
	// Consider validation successful if any of the combinations
	// specified in the authorization has been fulfilled
	validated := map[int]bool{}
	for i, ch := range authz.Challenges {
		if ch.Status == core.StatusValid {
			validated[i] = true
		}
	}
	for _, combo := range authz.Combinations {
		comboValid := true
		for _, i := range combo {
			if !validated[i] {
				comboValid = false
				break
			}
		}
		if comboValid {
			authz.Status = core.StatusValid
		}
	}

	// If no validation succeeded, then the authorization is invalid
	// NOTE: This only works because we only ever do one validation
	if authz.Status != core.StatusValid {
		authz.Status = core.StatusInvalid
	} else {
		// TODO: Enable configuration of expiry time
		exp := ra.clk.Now().Add(365 * 24 * time.Hour)
		authz.Expires = &exp
	}

	// Finalize the authorization (error ignored)
	return ra.SA.FinalizeAuthorization(authz)
}
