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
	"strings"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/golang.org/x/net/publicsuffix"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

// 10 month default authorization lifetime. When used with a 90-day cert
// lifetime, this allows creation of certs that will cover a whole year,
// plus a grace period of a month.
// TODO(jsha): Read from a config file.
const DefaultAuthorizationLifetime = 300 * 24 * time.Hour

// RegistrationAuthorityImpl defines an RA.
//
// NOTE: All of the fields in RegistrationAuthorityImpl need to be
// populated, or there is a risk of panic.
type RegistrationAuthorityImpl struct {
	CA          core.CertificateAuthority
	VA          core.ValidationAuthority
	SA          core.StorageAuthority
	PA          core.PolicyAuthority
	stats       statsd.Statter
	DNSResolver core.DNSResolver
	clk         clock.Clock
	log         *blog.AuditLogger
	// How long before a newly created authorization expires.
	authorizationLifetime time.Duration
	rlPolicies            cmd.RateLimitConfig
	tiMu                  *sync.RWMutex
	totalIssuedCache      int
	lastIssuedCount       *time.Time
}

// NewRegistrationAuthorityImpl constructs a new RA object.
func NewRegistrationAuthorityImpl(clk clock.Clock, logger *blog.AuditLogger, stats statsd.Statter, policies cmd.RateLimitConfig) RegistrationAuthorityImpl {
	ra := RegistrationAuthorityImpl{
		stats: stats,
		clk:   clk,
		log:   logger,
		authorizationLifetime: DefaultAuthorizationLifetime,
		rlPolicies:            policies,
		tiMu:                  new(sync.RWMutex),
	}
	return ra
}

func validateEmail(address string, resolver core.DNSResolver) (rtt time.Duration, err error) {
	_, err = mail.ParseAddress(address)
	if err != nil {
		err = core.MalformedRequestError(fmt.Sprintf("%s is not a valid e-mail address", address))
		return
	}
	splitEmail := strings.SplitN(address, "@", -1)
	domain := strings.ToLower(splitEmail[len(splitEmail)-1])
	var mx []string
	mx, rtt, err = resolver.LookupMX(domain)
	if err != nil || len(mx) == 0 {
		err = core.MalformedRequestError(fmt.Sprintf("No MX record for domain %s", domain))
		return
	}

	return
}

var issuanceCountCacheLife = 1 * time.Minute

// issuanceCountInvalid checks if the current issuance count is invalid either
// because it hasn't been set yet or because it has expired. This method expects
// that the caller holds either a R or W ra.tiMu lock.
func (ra *RegistrationAuthorityImpl) issuanceCountInvalid(now time.Time) bool {
	return ra.lastIssuedCount == nil || ra.lastIssuedCount.Add(issuanceCountCacheLife).Before(now)
}

func (ra *RegistrationAuthorityImpl) getIssuanceCount() (int, error) {
	ra.tiMu.RLock()
	if ra.issuanceCountInvalid(ra.clk.Now()) {
		ra.tiMu.RUnlock()
		return ra.setIssuanceCount()
	}
	count := ra.totalIssuedCache
	ra.tiMu.RUnlock()
	return count, nil
}

func (ra *RegistrationAuthorityImpl) setIssuanceCount() (int, error) {
	ra.tiMu.Lock()
	defer ra.tiMu.Unlock()

	now := ra.clk.Now()
	if ra.issuanceCountInvalid(now) {
		count, err := ra.SA.CountCertificatesRange(
			now.Add(-ra.rlPolicies.TotalCertificates.Window.Duration),
			now,
		)
		if err != nil {
			return 0, err
		}
		ra.totalIssuedCache = int(count)
		ra.lastIssuedCount = &now
	}
	return ra.totalIssuedCache, nil
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

	err = validateContacts(reg.Contact, ra.DNSResolver, ra.stats)
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

	ra.stats.Inc("RA.NewRegistrations", 1, 1.0)
	return
}

func validateContacts(contacts []*core.AcmeURL, resolver core.DNSResolver, stats statsd.Statter) (err error) {
	for _, contact := range contacts {
		switch contact.Scheme {
		case "tel":
			continue
		case "mailto":
			rtt, err := validateEmail(contact.Opaque, resolver)
			stats.TimingDuration("RA.DNS.RTT.MX", rtt, 1.0)
			stats.Inc("RA.DNS.Rate", 1, 1.0)
			if err != nil {
				return err
			}
		default:
			err = core.MalformedRequestError(fmt.Sprintf("Contact method %s is not supported", contact.Scheme))
			return
		}
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
	if err = ra.PA.WillingToIssue(identifier, regID); err != nil {
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

	// Create validations. The WFE will  update them with URIs before sending them out.
	challenges, combinations, err := ra.PA.ChallengesFor(identifier, &reg.Key)

	expires := ra.clk.Now().Add(ra.authorizationLifetime)

	// Partially-filled object
	authz = core.Authorization{
		Identifier:     identifier,
		RegistrationID: regID,
		Status:         core.StatusPending,
		Combinations:   combinations,
		Challenges:     challenges,
		// TODO(jsha): Pending authz should expire earlier than finalized authz.
		Expires: &expires,
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

// checkAuthorizations checks that each requested name has a valid authorization
// that won't expire before the certificate expires. Returns an error otherwise.
func (ra *RegistrationAuthorityImpl) checkAuthorizations(names []string, registration *core.Registration) (time.Time, error) {
	now := ra.clk.Now()

	firstRun := true
	var earliestExpiration time.Time
	var badNames []string
	for _, name := range names {
		authz, err := ra.SA.GetLatestValidAuthorization(registration.ID, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: name})

		// Ignore authorizations with no expiration; they are mal-formed
		if authz.Expires == nil {
			continue
		}

		if err != nil || authz.Expires.Before(now) {
			badNames = append(badNames, name)
		}

		if firstRun || authz.Expires.Before(earliestExpiration) {
			earliestExpiration = *authz.Expires
		}
		firstRun = false
	}

	if len(badNames) > 0 {
		return earliestExpiration, core.UnauthorizedError(fmt.Sprintf(
			"Authorizations for these names not found or expired: %s",
			strings.Join(badNames, ", ")))
	}
	return earliestExpiration, nil
}

// NewCertificate requests the issuance of a certificate.
func (ra *RegistrationAuthorityImpl) NewCertificate(req core.CertificateRequest) (cert core.CertificateRequest, err error) {
	emptyCertRequest := core.CertificateRequest{}
	var logEventResult string

	// Assume the worst
	logEventResult = "error"

	// Construct the log event
	logEvent := blog.CertificateRequestEvent{
		ID:            core.NewToken(),
		Requester:     req.RegistrationID,
		RequestMethod: "online",
		RequestTime:   ra.clk.Now(),
	}

	// No matter what, log the request
	defer func() {
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ra.log.AuditObject(fmt.Sprintf("Certificate request - %s", logEventResult), logEvent)
	}()

	if !req.ReadyForRA() {
		err = core.MalformedRequestError("Incomplete certificate request")
		return emptyCertRequest, err
	}

	if req.RegistrationID <= 0 {
		err = core.MalformedRequestError(fmt.Sprintf("Invalid registration ID: %d", req.RegistrationID))
		return emptyCertRequest, err
	}

	registration, err := ra.SA.GetRegistration(req.RegistrationID)
	if err != nil {
		logEvent.Error = err.Error()
		return emptyCertRequest, err
	}

	// Parse and verify the CSR
	csr, err := x509.ParseCertificateRequest(req.CSR)
	if err != nil {
		logEvent.Error = err.Error()
		err = core.UnauthorizedError("Failed to parse CSR")
		return emptyCertRequest, err
	}
	if err = core.VerifyCSR(csr); err != nil {
		logEvent.Error = err.Error()
		err = core.UnauthorizedError("Invalid signature on CSR")
		return emptyCertRequest, err
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
		return emptyCertRequest, err
	}

	csrPreviousDenied, err := ra.SA.AlreadyDeniedCSR(names)
	if err != nil {
		logEvent.Error = err.Error()
		return emptyCertRequest, err
	}
	if csrPreviousDenied {
		err = core.UnauthorizedError("CSR has already been revoked/denied")
		logEvent.Error = err.Error()
		return emptyCertRequest, err
	}

	if core.KeyDigestEquals(csr.PublicKey, registration.Key) {
		err = core.MalformedRequestError("Certificate public key must be different than account key")
		return emptyCertRequest, err
	}

	// Check rate limits before checking authorizations. If someone is unable to
	// issue a cert due to rate limiting, we don't want to tell them to go get the
	// necessary authorizations, only to later fail the rate limit check.
	err = ra.checkLimits(names, registration.ID)
	if err != nil {
		logEvent.Error = err.Error()
		return emptyCertRequest, err
	}

	earliestExpiration, err := ra.checkAuthorizations(names, &registration)
	if err != nil {
		logEvent.Error = err.Error()
		return emptyCertRequest, err
	}
	req.Expires = earliestExpiration

	// Mark that we verified the CN and SANs
	logEvent.VerifiedFields = []string{"subject.commonName", "subjectAltName"}

	// Verify that the CA is willing to issue for this CSR
	if req, err = ra.CA.NewCertificateRequest(req); err != nil {
		logEvent.Error = err.Error()
		return emptyCertRequest, err
	}

	// Request that the CA issue the certificate
	if err = ra.CA.IssueCertificate(req.ID, logEvent.ID); err != nil {
		logEvent.Error = err.Error()
		return emptyCertRequest, err
	}

	logEventResult = "successful"

	ra.stats.Inc("RA.NewCertificates", 1, 1.0)
	return req, nil
}

// domainsForRateLimiting transforms a list of FQDNs into a list of eTLD+1's
// for the purpose of rate limiting. It also de-duplicates the output
// domains.
func domainsForRateLimiting(names []string) ([]string, error) {
	domainsMap := make(map[string]struct{}, len(names))
	var domains []string
	for _, name := range names {
		eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(name)
		if err != nil {
			return nil, err
		}
		if _, ok := domainsMap[eTLDPlusOne]; !ok {
			domainsMap[eTLDPlusOne] = struct{}{}
			domains = append(domains, eTLDPlusOne)
		}
	}
	return domains, nil
}

func (ra *RegistrationAuthorityImpl) checkCertificatesPerNameLimit(names []string, limit cmd.RateLimitPolicy, regID int64) error {
	names, err := domainsForRateLimiting(names)
	if err != nil {
		return err
	}
	now := ra.clk.Now()
	windowBegin := limit.WindowBegin(now)
	counts, err := ra.SA.CountCertificatesByNames(names, windowBegin, now)
	if err != nil {
		return err
	}
	var badNames []string
	for _, name := range names {
		count, ok := counts[name]
		if !ok {
			// Shouldn't happen, but let's be careful anyhow.
			return errors.New("StorageAuthority failed to return a count for every name")
		}
		if count >= limit.GetThreshold(name, regID) {
			badNames = append(badNames, name)
		}
	}
	if len(badNames) > 0 {
		return core.RateLimitedError(fmt.Sprintf(
			"Too many certificates already issued for: %s",
			strings.Join(badNames, ", ")))
	}
	return nil
}

func (ra *RegistrationAuthorityImpl) checkLimits(names []string, regID int64) error {
	limits := ra.rlPolicies
	if limits.TotalCertificates.Enabled() {
		totalIssued, err := ra.getIssuanceCount()
		if err != nil {
			return err
		}
		if totalIssued >= ra.rlPolicies.TotalCertificates.Threshold {
			return core.RateLimitedError("Certificate issuance limit reached")
		}
	}
	if limits.CertificatesPerName.Enabled() {
		err := ra.checkCertificatesPerNameLimit(names, limits.CertificatesPerName, regID)
		if err != nil {
			return err
		}
	}
	return nil
}

// UpdateRegistration updates an existing Registration with new values.
func (ra *RegistrationAuthorityImpl) UpdateRegistration(base core.Registration, update core.Registration) (reg core.Registration, err error) {
	base.MergeUpdate(update)

	err = validateContacts(base.Contact, ra.DNSResolver, ra.stats)
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

	ra.stats.Inc("RA.UpdatedRegistrations", 1, 1.0)
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

	// At this point, the challenge should be sane as a complete challenge
	if !authz.Challenges[challengeIndex].IsSane(true) {
		err = core.MalformedRequestError("Response does not complete challenge")
		return
	}

	// Store the updated version
	if err = ra.SA.UpdatePendingAuthorization(authz); err != nil {
		// This can pretty much only happen when the client corrupts the Challenge
		// data.
		err = core.MalformedRequestError("Challenge data was corrupted")
		return
	}
	ra.stats.Inc("RA.NewPendingAuthorizations", 1, 1.0)

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

	ra.stats.Inc("RA.UpdatedPendingAuthorizations", 1, 1.0)
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
	ra.stats.Inc("RA.RevokedCertificates", 1, 1.0)
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
		exp := ra.clk.Now().Add(ra.authorizationLifetime)
		authz.Expires = &exp
	}

	// Finalize the authorization
	err := ra.SA.FinalizeAuthorization(authz)
	if err != nil {
		return err
	}

	ra.stats.Inc("RA.FinalizedAuthorizations", 1, 1.0)
	return nil
}
