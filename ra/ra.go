package ra

import (
	"crypto/x509"
	"errors"
	"expvar"
	"fmt"
	"net"
	"net/mail"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cactus/go-statsd-client/statsd"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/goodkey"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/reloader"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/core"
	csrlib "github.com/letsencrypt/boulder/csr"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/ratelimit"
	vaPB "github.com/letsencrypt/boulder/va/proto"
	oldx509 "github.com/letsencrypt/go/src/crypto/x509"
)

// Note: the issuanceExpvar must be a global. If it is a member of the RA, or
// initialized with everything else in NewRegistrationAuthority() then multiple
// invocations of the constructor (e.g from unit tests) will panic with a "Reuse
// of exported var name:" error from the expvar package.
var issuanceExpvar = expvar.NewInt("lastIssuance")

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
	DNSResolver bdns.DNSResolver
	clk         clock.Clock
	log         blog.Logger
	keyPolicy   goodkey.KeyPolicy
	// How long before a newly created authorization expires.
	authorizationLifetime        time.Duration
	pendingAuthorizationLifetime time.Duration
	rlPolicies                   ratelimit.Limits
	tiMu                         *sync.RWMutex
	totalIssuedCache             int
	lastIssuedCount              *time.Time
	maxContactsPerReg            int
	maxNames                     int
	forceCNFromSAN               bool
	reuseValidAuthz              bool

	regByIPStats         metrics.Scope
	pendAuthByRegIDStats metrics.Scope
	certsForDomainStats  metrics.Scope
	totalCertsStats      metrics.Scope
}

// NewRegistrationAuthorityImpl constructs a new RA object.
func NewRegistrationAuthorityImpl(
	clk clock.Clock,
	logger blog.Logger,
	stats statsd.Statter,
	maxContactsPerReg int,
	keyPolicy goodkey.KeyPolicy,
	maxNames int,
	forceCNFromSAN bool,
	reuseValidAuthz bool,
	authorizationLifetime time.Duration,
	pendingAuthorizationLifetime time.Duration,
) *RegistrationAuthorityImpl {
	scope := metrics.NewStatsdScope(stats, "RA")
	ra := &RegistrationAuthorityImpl{
		stats: stats,
		clk:   clk,
		log:   logger,
		authorizationLifetime:        authorizationLifetime,
		pendingAuthorizationLifetime: pendingAuthorizationLifetime,
		rlPolicies:                   ratelimit.New(),
		tiMu:                         new(sync.RWMutex),
		maxContactsPerReg:            maxContactsPerReg,
		keyPolicy:                    keyPolicy,
		maxNames:                     maxNames,
		forceCNFromSAN:               forceCNFromSAN,
		reuseValidAuthz:              reuseValidAuthz,
		regByIPStats:                 scope.NewScope("RA", "RateLimit", "RegistrationsByIP"),
		pendAuthByRegIDStats:         scope.NewScope("RA", "RateLimit", "PendingAuthorizationsByRegID"),
		certsForDomainStats:          scope.NewScope("RA", "RateLimit", "CertificatesForDomain"),
		totalCertsStats:              scope.NewScope("RA", "RateLimit", "TotalCertificates"),
	}
	return ra
}

func (ra *RegistrationAuthorityImpl) SetRateLimitPoliciesFile(filename string) error {
	_, err := reloader.New(filename, ra.rlPolicies.LoadPolicies, ra.rateLimitPoliciesLoadError)
	if err != nil {
		return err
	}

	return nil
}

func (ra *RegistrationAuthorityImpl) rateLimitPoliciesLoadError(err error) {
	ra.log.Err(fmt.Sprintf("error reloading rate limit policy: %s", err))
}

const (
	unparseableEmailDetail = "not a valid e-mail address"
	emptyDNSResponseDetail = "empty DNS response"
	multipleAddressDetail  = "more than one e-mail address"
)

func validateEmail(ctx context.Context, address string, resolver bdns.DNSResolver) (prob *probs.ProblemDetails) {
	emails, err := mail.ParseAddressList(address)
	if err != nil {
		return probs.InvalidEmail(unparseableEmailDetail)
	}
	if len(emails) > 1 {
		return probs.InvalidEmail(multipleAddressDetail)
	}
	splitEmail := strings.SplitN(emails[0].Address, "@", -1)
	domain := strings.ToLower(splitEmail[len(splitEmail)-1])
	var resultMX []string
	var resultA []net.IP
	var errMX, errA error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		resultMX, errMX = resolver.LookupMX(ctx, domain)
		wg.Done()
	}()
	go func() {
		resultA, errA = resolver.LookupHost(ctx, domain)
		wg.Done()
	}()
	wg.Wait()

	if errMX != nil {
		prob := bdns.ProblemDetailsFromDNSError(errMX)
		prob.Type = probs.InvalidEmailProblem
		return prob
	} else if len(resultMX) > 0 {
		return nil
	}
	if errA != nil {
		prob := bdns.ProblemDetailsFromDNSError(errA)
		prob.Type = probs.InvalidEmailProblem
		return prob
	} else if len(resultA) > 0 {
		return nil
	}

	return probs.InvalidEmail(emptyDNSResponseDetail)
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

var issuanceCountCacheLife = 1 * time.Minute

// issuanceCountInvalid checks if the current issuance count is invalid either
// because it hasn't been set yet or because it has expired. This method expects
// that the caller holds either a R or W ra.tiMu lock.
func (ra *RegistrationAuthorityImpl) issuanceCountInvalid(now time.Time) bool {
	return ra.lastIssuedCount == nil || ra.lastIssuedCount.Add(issuanceCountCacheLife).Before(now)
}

func (ra *RegistrationAuthorityImpl) getIssuanceCount(ctx context.Context) (int, error) {
	ra.tiMu.RLock()
	if ra.issuanceCountInvalid(ra.clk.Now()) {
		ra.tiMu.RUnlock()
		return ra.setIssuanceCount(ctx)
	}
	count := ra.totalIssuedCache
	ra.tiMu.RUnlock()
	return count, nil
}

func (ra *RegistrationAuthorityImpl) setIssuanceCount(ctx context.Context) (int, error) {
	ra.tiMu.Lock()
	defer ra.tiMu.Unlock()

	totalCertWindow := ra.rlPolicies.TotalCertificates().Window.Duration

	now := ra.clk.Now()
	if ra.issuanceCountInvalid(now) {
		count, err := ra.SA.CountCertificatesRange(
			ctx,
			now.Add(-totalCertWindow),
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

// noRegistrationID is used for the regID parameter to GetThreshold when no
// registration-based overrides are necessary.
const noRegistrationID = -1

func (ra *RegistrationAuthorityImpl) checkRegistrationLimit(ctx context.Context, ip net.IP) error {
	limit := ra.rlPolicies.RegistrationsPerIP()

	if limit.Enabled() {
		now := ra.clk.Now()
		count, err := ra.SA.CountRegistrationsByIP(ctx, ip, limit.WindowBegin(now), now)
		if err != nil {
			return err
		}
		if count >= limit.GetThreshold(ip.String(), noRegistrationID) {
			ra.regByIPStats.Inc("Exceeded", 1)
			ra.log.Info(fmt.Sprintf("Rate limit exceeded, RegistrationsByIP, IP: %s", ip))
			return core.RateLimitedError("Too many registrations from this IP")
		}
		ra.regByIPStats.Inc("Pass", 1)
	}
	return nil
}

// NewRegistration constructs a new Registration from a request.
func (ra *RegistrationAuthorityImpl) NewRegistration(ctx context.Context, init core.Registration) (reg core.Registration, err error) {
	if err = ra.keyPolicy.GoodKey(init.Key.Key); err != nil {
		return core.Registration{}, core.MalformedRequestError(fmt.Sprintf("Invalid public key: %s", err.Error()))
	}
	if err = ra.checkRegistrationLimit(ctx, init.InitialIP); err != nil {
		return core.Registration{}, err
	}

	reg = core.Registration{
		Key: init.Key,
	}
	_ = reg.MergeUpdate(init)

	// This field isn't updatable by the end user, so it isn't copied by
	// MergeUpdate. But we need to fill it in for new registrations.
	reg.InitialIP = init.InitialIP

	err = ra.validateContacts(ctx, reg.Contact)
	if err != nil {
		return
	}

	// Store the authorization object, then return it
	reg, err = ra.SA.NewRegistration(ctx, reg)
	if err != nil {
		// InternalServerError since the user-data was validated before being
		// passed to the SA.
		err = core.InternalServerError(err.Error())
	}

	ra.stats.Inc("RA.NewRegistrations", 1, 1.0)
	return
}

func (ra *RegistrationAuthorityImpl) validateContacts(ctx context.Context, contacts *[]*core.AcmeURL) error {
	if contacts == nil || len(*contacts) == 0 {
		return nil // Nothing to validate
	}
	if ra.maxContactsPerReg > 0 && len(*contacts) > ra.maxContactsPerReg {
		return core.MalformedRequestError(fmt.Sprintf("Too many contacts provided: %d > %d",
			len(*contacts), ra.maxContactsPerReg))
	}

	for _, contact := range *contacts {
		if contact == nil {
			return core.MalformedRequestError("Invalid contact")
		}
		if contact.Scheme != "mailto" {
			return core.MalformedRequestError(fmt.Sprintf("Contact method %s is not supported", contact.Scheme))
		}
		if !core.IsASCII(contact.String()) {
			return core.MalformedRequestError(
				fmt.Sprintf("Contact email [%s] contains non-ASCII characters", contact.String()))
		}

		start := ra.clk.Now()
		ra.stats.Inc("RA.ValidateEmail.Calls", 1, 1.0)
		problem := validateEmail(ctx, contact.Opaque, ra.DNSResolver)
		ra.stats.TimingDuration("RA.ValidateEmail.Latency", ra.clk.Now().Sub(start), 1.0)
		if problem != nil {
			ra.stats.Inc("RA.ValidateEmail.Errors", 1, 1.0)
			return problem
		}
		ra.stats.Inc("RA.ValidateEmail.Successes", 1, 1.0)
	}

	return nil
}

func (ra *RegistrationAuthorityImpl) checkPendingAuthorizationLimit(ctx context.Context, regID int64) error {
	limit := ra.rlPolicies.PendingAuthorizationsPerAccount()
	if limit.Enabled() {
		count, err := ra.SA.CountPendingAuthorizations(ctx, regID)
		if err != nil {
			return err
		}
		// Most rate limits have a key for overrides, but there is no meaningful key
		// here.
		noKey := ""
		if count >= limit.GetThreshold(noKey, regID) {
			ra.pendAuthByRegIDStats.Inc("Exceeded", 1)
			ra.log.Info(fmt.Sprintf("Rate limit exceeded, PendingAuthorizationsByRegID, regID: %d", regID))
			return core.RateLimitedError("Too many currently pending authorizations.")
		}
		ra.pendAuthByRegIDStats.Inc("Pass", 1)
	}
	return nil
}

// NewAuthorization constructs a new Authz from a request. Values (domains) in
// request.Identifier will be lowercased before storage.
func (ra *RegistrationAuthorityImpl) NewAuthorization(ctx context.Context, request core.Authorization, regID int64) (authz core.Authorization, err error) {
	identifier := request.Identifier
	identifier.Value = strings.ToLower(identifier.Value)

	// Check that the identifier is present and appropriate
	if err = ra.PA.WillingToIssue(identifier); err != nil {
		return authz, err
	}

	if err = ra.checkPendingAuthorizationLimit(ctx, regID); err != nil {
		return authz, err
	}

	if identifier.Type == core.IdentifierDNS {
		isSafeResp, err := ra.VA.IsSafeDomain(ctx, &vaPB.IsSafeDomainRequest{Domain: &identifier.Value})
		if err != nil {
			outErr := core.InternalServerError("unable to determine if domain was safe")
			ra.log.Warning(fmt.Sprintf("%s: %s", string(outErr), err))
			return authz, outErr
		}
		if !isSafeResp.GetIsSafe() {
			return authz, core.UnauthorizedError(fmt.Sprintf("%#v was considered an unsafe domain by a third-party API", identifier.Value))
		}
	}

	if ra.reuseValidAuthz {
		auths, err := ra.SA.GetValidAuthorizations(ctx, regID, []string{identifier.Value}, ra.clk.Now())
		if err != nil {
			outErr := core.InternalServerError(
				fmt.Sprintf("unable to get existing validations for regID: %d, identifier: %s",
					regID, identifier.Value))
			ra.log.Warning(string(outErr))
		}

		if existingAuthz, ok := auths[identifier.Value]; ok {
			// Use the valid existing authorization's ID to find a fully populated version
			// The results from `GetValidAuthorizations` are most notably missing
			// `Challenge` values that the client expects in the result.
			populatedAuthz, err := ra.SA.GetAuthorization(ctx, existingAuthz.ID)
			if err != nil {
				outErr := core.InternalServerError(
					fmt.Sprintf("unable to get existing authorization for auth ID: %s",
						existingAuthz.ID))
				ra.log.Warning(fmt.Sprintf("%s: %s", string(outErr), existingAuthz.ID))
			}

			// The existing authorization must not expire within the next 24 hours for
			// it to be OK for reuse
			reuseCutOff := ra.clk.Now().Add(time.Hour * 24)
			if populatedAuthz.Expires.After(reuseCutOff) {
				ra.stats.Inc("RA.ReusedValidAuthz", 1, 1.0)
				return populatedAuthz, nil
			}
		}
	}

	// Create validations. The WFE will  update them with URIs before sending them out.
	challenges, combinations := ra.PA.ChallengesFor(identifier)

	expires := ra.clk.Now().Add(ra.pendingAuthorizationLifetime)

	// Partially-filled object
	authz = core.Authorization{
		Identifier:     identifier,
		RegistrationID: regID,
		Status:         core.StatusPending,
		Combinations:   combinations,
		Challenges:     challenges,
		Expires:        &expires,
	}

	// Get a pending Auth first so we can get our ID back, then update with challenges
	authz, err = ra.SA.NewPendingAuthorization(ctx, authz)
	if err != nil {
		// InternalServerError since the user-data was validated before being
		// passed to the SA.
		err = core.InternalServerError(fmt.Sprintf("Invalid authorization request: %s", err))
		return core.Authorization{}, err
	}

	// Check each challenge for sanity.
	for _, challenge := range authz.Challenges {
		if !challenge.IsSaneForClientOffer() {
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
//		* notBefore is not more than 24 hours ago
//		* BasicConstraintsValid is true
//		* IsCA is false
//		* ExtKeyUsage only contains ExtKeyUsageServerAuth & ExtKeyUsageClientAuth
//		* Subject only contains CommonName & Names
func (ra *RegistrationAuthorityImpl) MatchesCSR(cert core.Certificate, csr *oldx509.CertificateRequest) (err error) {
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
	hostNames = core.UniqueLowerNames(hostNames)

	if !core.KeyDigestEquals(parsedCertificate.PublicKey, csr.PublicKey) {
		err = core.InternalServerError("Generated certificate public key doesn't match CSR public key")
		return
	}
	if !ra.forceCNFromSAN && len(csr.Subject.CommonName) > 0 &&
		parsedCertificate.Subject.CommonName != strings.ToLower(csr.Subject.CommonName) {
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
		len(parsedCertificate.Subject.PostalCode) > 0 {
		err = core.InternalServerError("Generated certificate Subject contains fields other than CommonName, or SerialNumber")
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

// checkAuthorizations checks that each requested name has a valid authorization
// that won't expire before the certificate expires. Returns an error otherwise.
func (ra *RegistrationAuthorityImpl) checkAuthorizations(ctx context.Context, names []string, registration *core.Registration) error {
	now := ra.clk.Now()
	var badNames []string
	for i := range names {
		names[i] = strings.ToLower(names[i])
	}
	auths, err := ra.SA.GetValidAuthorizations(ctx, registration.ID, names, now)
	if err != nil {
		return err
	}
	for _, name := range names {
		authz := auths[name]
		if authz == nil {
			badNames = append(badNames, name)
		} else if authz.Expires == nil {
			return fmt.Errorf("Found an authorization with a nil Expires field: id %s", authz.ID)
		} else if authz.Expires.Before(now) {
			badNames = append(badNames, name)
		}
	}

	if len(badNames) > 0 {
		return core.UnauthorizedError(fmt.Sprintf(
			"Authorizations for these names not found or expired: %s",
			strings.Join(badNames, ", ")))
	}
	return nil
}

// NewCertificate requests the issuance of a certificate.
func (ra *RegistrationAuthorityImpl) NewCertificate(ctx context.Context, req core.CertificateRequest, regID int64) (cert core.Certificate, err error) {
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

	registration, err := ra.SA.GetRegistration(ctx, regID)
	if err != nil {
		logEvent.Error = err.Error()
		return emptyCert, err
	}

	// Verify the CSR
	csr := req.CSR
	if err := csrlib.VerifyCSR(csr, ra.maxNames, &ra.keyPolicy, ra.PA, ra.forceCNFromSAN, regID); err != nil {
		err = core.MalformedRequestError(err.Error())
		return emptyCert, err
	}

	logEvent.CommonName = csr.Subject.CommonName
	logEvent.Names = csr.DNSNames

	// Validate that authorization key is authorized for all domains
	names := make([]string, len(csr.DNSNames))
	copy(names, csr.DNSNames)

	if len(names) == 0 {
		err = core.UnauthorizedError("CSR has no names in it")
		logEvent.Error = err.Error()
		return emptyCert, err
	}

	if core.KeyDigestEquals(csr.PublicKey, registration.Key) {
		err = core.MalformedRequestError("Certificate public key must be different than account key")
		return emptyCert, err
	}

	// Check rate limits before checking authorizations. If someone is unable to
	// issue a cert due to rate limiting, we don't want to tell them to go get the
	// necessary authorizations, only to later fail the rate limit check.
	err = ra.checkLimits(ctx, names, registration.ID)
	if err != nil {
		logEvent.Error = err.Error()
		return emptyCert, err
	}

	err = ra.checkAuthorizations(ctx, names, &registration)
	if err != nil {
		logEvent.Error = err.Error()
		return emptyCert, err
	}

	// Mark that we verified the CN and SANs
	logEvent.VerifiedFields = []string{"subject.commonName", "subjectAltName"}

	// Create the certificate and log the result
	if cert, err = ra.CA.IssueCertificate(ctx, *csr, regID); err != nil {
		logEvent.Error = err.Error()
		return emptyCert, err
	}

	err = ra.MatchesCSR(cert, csr)
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

	now := ra.clk.Now()
	logEvent.SerialNumber = core.SerialToString(parsedCertificate.SerialNumber)
	logEvent.CommonName = parsedCertificate.Subject.CommonName
	logEvent.NotBefore = parsedCertificate.NotBefore
	logEvent.NotAfter = parsedCertificate.NotAfter
	logEvent.ResponseTime = now

	logEventResult = "successful"

	issuanceExpvar.Set(now.Unix())
	ra.stats.Inc("RA.NewCertificates", 1, 1.0)
	return cert, nil
}

// domainsForRateLimiting transforms a list of FQDNs into a list of eTLD+1's
// for the purpose of rate limiting. It also de-duplicates the output
// domains.
func domainsForRateLimiting(names []string) ([]string, error) {
	domainsMap := make(map[string]struct{}, len(names))
	var domains []string
	for _, name := range names {
		domain, err := publicsuffix.Domain(name)
		if err != nil {
			// The only possible errors are:
			// (1) publicsuffix.Domain is giving garbage values
			// (2) the public suffix is the domain itself
			//
			// Assume (2).
			domain = name
		}
		if _, ok := domainsMap[domain]; !ok {
			domainsMap[domain] = struct{}{}
			domains = append(domains, domain)
		}
	}
	return domains, nil
}

func (ra *RegistrationAuthorityImpl) checkCertificatesPerNameLimit(ctx context.Context, names []string, limit ratelimit.RateLimitPolicy, regID int64) error {
	tldNames, err := domainsForRateLimiting(names)
	if err != nil {
		return err
	}
	now := ra.clk.Now()
	windowBegin := limit.WindowBegin(now)
	counts, err := ra.SA.CountCertificatesByNames(ctx, tldNames, windowBegin, now)
	if err != nil {
		return err
	}
	var badNames []string
	for _, name := range tldNames {
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
		// check if there is already a existing certificate for
		// the exact name set we are issuing for. If so bypass the
		// the certificatesPerName limit.
		exists, err := ra.SA.FQDNSetExists(ctx, names)
		if err != nil {
			return err
		}
		if exists {
			ra.certsForDomainStats.Inc("FQDNSetBypass", 1)
			return nil
		}
		domains := strings.Join(badNames, ", ")
		ra.certsForDomainStats.Inc("Exceeded", 1)
		ra.log.Info(fmt.Sprintf("Rate limit exceeded, CertificatesForDomain, regID: %d, domains: %s", regID, domains))
		return core.RateLimitedError(fmt.Sprintf(
			"Too many certificates already issued for: %s", domains))

	}
	ra.certsForDomainStats.Inc("Pass", 1)

	return nil
}

func (ra *RegistrationAuthorityImpl) checkCertificatesPerFQDNSetLimit(ctx context.Context, names []string, limit ratelimit.RateLimitPolicy, regID int64) error {
	count, err := ra.SA.CountFQDNSets(ctx, limit.Window.Duration, names)
	if err != nil {
		return err
	}
	names = core.UniqueLowerNames(names)
	if int(count) > limit.GetThreshold(strings.Join(names, ","), regID) {
		return core.RateLimitedError(fmt.Sprintf(
			"Too many certificates already issued for exact set of domains: %s",
			strings.Join(names, ","),
		))
	}
	return nil
}

func (ra *RegistrationAuthorityImpl) checkLimits(ctx context.Context, names []string, regID int64) error {
	totalCertLimits := ra.rlPolicies.TotalCertificates()
	if totalCertLimits.Enabled() {
		totalIssued, err := ra.getIssuanceCount(ctx)
		if err != nil {
			return err
		}
		if totalIssued >= totalCertLimits.Threshold {
			domains := strings.Join(names, ",")
			ra.totalCertsStats.Inc("Exceeded", 1)
			ra.log.Info(fmt.Sprintf("Rate limit exceeded, TotalCertificates, regID: %d, domains: %s, totalIssued: %d", regID, domains, totalIssued))
			return core.RateLimitedError("Certificate issuance limit reached")
		}
		ra.totalCertsStats.Inc("Pass", 1)
	}

	certNameLimits := ra.rlPolicies.CertificatesPerName()
	if certNameLimits.Enabled() {
		err := ra.checkCertificatesPerNameLimit(ctx, names, certNameLimits, regID)
		if err != nil {
			return err
		}
	}

	fqdnLimits := ra.rlPolicies.CertificatesPerFQDNSet()
	if fqdnLimits.Enabled() {
		err := ra.checkCertificatesPerFQDNSetLimit(ctx, names, fqdnLimits, regID)
		if err != nil {
			return err
		}
	}
	return nil
}

// UpdateRegistration updates an existing Registration with new values.
func (ra *RegistrationAuthorityImpl) UpdateRegistration(ctx context.Context, base core.Registration, update core.Registration) (core.Registration, error) {
	if changed := base.MergeUpdate(update); !changed {
		// If merging the update didn't actually change the base then our work is
		// done, we can return before calling ra.SA.UpdateRegistration since theres
		// nothing for the SA to do
		return base, nil
	}

	err := ra.validateContacts(ctx, base.Contact)
	if err != nil {
		return core.Registration{}, err
	}

	err = ra.SA.UpdateRegistration(ctx, base)
	if err != nil {
		// InternalServerError since the user-data was validated before being
		// passed to the SA.
		err = core.InternalServerError(fmt.Sprintf("Could not update registration: %s", err))
		return core.Registration{}, err
	}

	ra.stats.Inc("RA.UpdatedRegistrations", 1, 1.0)
	return base, nil
}

// UpdateAuthorization updates an authorization with new values.
func (ra *RegistrationAuthorityImpl) UpdateAuthorization(ctx context.Context, base core.Authorization, challengeIndex int, response core.Challenge) (authz core.Authorization, err error) {
	// Refuse to update expired authorizations
	if base.Expires == nil || base.Expires.Before(ra.clk.Now()) {
		err = core.NotFoundError("Expired authorization")
		return
	}

	authz = base
	if challengeIndex >= len(authz.Challenges) {
		err = core.MalformedRequestError(fmt.Sprintf("Invalid challenge index: %d", challengeIndex))
		return
	}

	ch := &authz.Challenges[challengeIndex]

	if response.Type != "" && ch.Type != response.Type {
		// TODO(riking): Check the rate on this, uncomment error return if negligible
		ra.stats.Inc("RA.StartChallengeWrongType", 1, 1.0)
		// err = core.MalformedRequestError(fmt.Sprintf("Invalid update to challenge - provided type was %s but actual type is %s", response.Type, ch.Type))
		// return
	}

	// When configured with `reuseValidAuthz` we can expect some clients to try
	// and update a challenge for an authorization that is already valid. In this
	// case we don't need to process the challenge update. It wouldn't be helpful,
	// the overall authorization is already good! We increment a stat for this
	// case and return early.
	if ra.reuseValidAuthz && authz.Status == core.StatusValid {
		ra.stats.Inc("RA.ReusedValidAuthzChallenge", 1, 1.0)
		return
	}

	// Look up the account key for this authorization
	reg, err := ra.SA.GetRegistration(ctx, authz.RegistrationID)
	if err != nil {
		err = core.InternalServerError(err.Error())
		return
	}

	// Recompute the key authorization field provided by the client and
	// check it against the value provided
	expectedKeyAuthorization, err := ch.ExpectedKeyAuthorization(&reg.Key)
	if err != nil {
		err = core.InternalServerError("Could not compute expected key authorization value")
		return
	}
	if expectedKeyAuthorization != response.ProvidedKeyAuthorization {
		err = core.MalformedRequestError("Provided key authorization was incorrect")
		return
	}

	// Copy information over that the client is allowed to supply
	ch.ProvidedKeyAuthorization = response.ProvidedKeyAuthorization

	// Double check before sending to VA
	if !ch.IsSaneForValidation() {
		err = core.MalformedRequestError("Response does not complete challenge")
		return
	}

	// Store the updated version
	if err = ra.SA.UpdatePendingAuthorization(ctx, authz); err != nil {
		// This can pretty much only happen when the client corrupts the Challenge
		// data.
		err = core.MalformedRequestError("Challenge data was corrupted")
		return
	}
	ra.stats.Inc("RA.NewPendingAuthorizations", 1, 1.0)

	// Dispatch to the VA for service

	vaCtx := context.Background()
	go func() {
		records, err := ra.VA.PerformValidation(vaCtx, authz.Identifier.Value, authz.Challenges[challengeIndex], authz)
		var prob *probs.ProblemDetails
		if p, ok := err.(*probs.ProblemDetails); ok {
			prob = p
		} else if err != nil {
			prob = probs.ServerInternal("Could not communicate with VA")
			ra.log.AuditErr(fmt.Sprintf("Could not communicate with VA: %s", err))
		}

		// Save the updated records
		challenge := &authz.Challenges[challengeIndex]
		challenge.ValidationRecord = records

		if !challenge.RecordsSane() && prob == nil {
			prob = probs.ServerInternal("Records for validation failed sanity check")
		}

		if prob != nil {
			challenge.Status = core.StatusInvalid
			challenge.Error = prob
		} else {
			challenge.Status = core.StatusValid
		}
		authz.Challenges[challengeIndex] = *challenge

		err = ra.onValidationUpdate(vaCtx, authz)
		if err != nil {
			ra.log.AuditErr(fmt.Sprintf("Could not record updated validation: err=[%s] regID=[%d]", err, authz.RegistrationID))
		}
	}()
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
func (ra *RegistrationAuthorityImpl) RevokeCertificateWithReg(ctx context.Context, cert x509.Certificate, revocationCode core.RevocationCode, regID int64) (err error) {
	serialString := core.SerialToString(cert.SerialNumber)
	err = ra.SA.MarkCertificateRevoked(ctx, serialString, revocationCode)

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
		ra.log.AuditInfo(fmt.Sprintf(
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
func (ra *RegistrationAuthorityImpl) AdministrativelyRevokeCertificate(ctx context.Context, cert x509.Certificate, revocationCode core.RevocationCode, user string) error {
	serialString := core.SerialToString(cert.SerialNumber)
	err := ra.SA.MarkCertificateRevoked(ctx, serialString, revocationCode)

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
		ra.log.AuditInfo(fmt.Sprintf(
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

// onValidationUpdate saves a validation's new status after receiving an
// authorization back from the VA.
func (ra *RegistrationAuthorityImpl) onValidationUpdate(ctx context.Context, authz core.Authorization) error {
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
	err := ra.SA.FinalizeAuthorization(ctx, authz)
	if err != nil {
		return err
	}

	ra.stats.Inc("RA.FinalizedAuthorizations", 1, 1.0)
	return nil
}
