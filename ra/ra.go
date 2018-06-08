package ra

import (
	"crypto/x509"
	"encoding/json"
	"expvar"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/bdns"
	caPB "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	csrlib "github.com/letsencrypt/boulder/csr"
	"github.com/letsencrypt/boulder/ctpolicy"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/probs"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/ratelimit"
	"github.com/letsencrypt/boulder/reloader"
	"github.com/letsencrypt/boulder/revocation"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	vaPB "github.com/letsencrypt/boulder/va/proto"
	"github.com/letsencrypt/boulder/web"
	grpc "google.golang.org/grpc"
)

// Note: the issuanceExpvar must be a global. If it is a member of the RA, or
// initialized with everything else in NewRegistrationAuthority() then multiple
// invocations of the constructor (e.g from unit tests) will panic with a "Reuse
// of exported var name:" error from the expvar package.
var issuanceExpvar = expvar.NewInt("lastIssuance")

type caaChecker interface {
	IsCAAValid(
		ctx context.Context,
		in *vaPB.IsCAAValidRequest,
		opts ...grpc.CallOption,
	) (*vaPB.IsCAAValidResponse, error)
}

// RegistrationAuthorityImpl defines an RA.
//
// NOTE: All of the fields in RegistrationAuthorityImpl need to be
// populated, or there is a risk of panic.
type RegistrationAuthorityImpl struct {
	CA        core.CertificateAuthority
	VA        core.ValidationAuthority
	SA        core.StorageAuthority
	PA        core.PolicyAuthority
	publisher core.Publisher
	caa       caaChecker

	stats     metrics.Scope
	DNSClient bdns.DNSClient
	clk       clock.Clock
	log       blog.Logger
	keyPolicy goodkey.KeyPolicy
	// How long before a newly created authorization expires.
	authorizationLifetime        time.Duration
	pendingAuthorizationLifetime time.Duration
	rlPolicies                   ratelimit.Limits
	maxContactsPerReg            int
	maxNames                     int
	forceCNFromSAN               bool
	reuseValidAuthz              bool
	orderLifetime                time.Duration

	regByIPStats           metrics.Scope
	regByIPRangeStats      metrics.Scope
	pendAuthByRegIDStats   metrics.Scope
	pendOrdersByRegIDStats metrics.Scope
	newOrderByRegIDStats   metrics.Scope
	certsForDomainStats    metrics.Scope

	ctpolicy        *ctpolicy.CTPolicy
	ctpolicyResults *prometheus.HistogramVec
}

// NewRegistrationAuthorityImpl constructs a new RA object.
func NewRegistrationAuthorityImpl(
	clk clock.Clock,
	logger blog.Logger,
	stats metrics.Scope,
	maxContactsPerReg int,
	keyPolicy goodkey.KeyPolicy,
	maxNames int,
	forceCNFromSAN bool,
	reuseValidAuthz bool,
	authorizationLifetime time.Duration,
	pendingAuthorizationLifetime time.Duration,
	pubc core.Publisher,
	caaClient caaChecker,
	orderLifetime time.Duration,
	ctp *ctpolicy.CTPolicy,
) *RegistrationAuthorityImpl {
	ctpolicyResults := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ctpolicy_results",
			Help:    "Histogram of latencies of ctpolicy.GetSCTs calls with success/failure/deadlineExceeded labels",
			Buckets: metrics.InternetFacingBuckets,
		},
		[]string{"result"},
	)
	stats.MustRegister(ctpolicyResults)

	ra := &RegistrationAuthorityImpl{
		stats: stats,
		clk:   clk,
		log:   logger,
		authorizationLifetime:        authorizationLifetime,
		pendingAuthorizationLifetime: pendingAuthorizationLifetime,
		rlPolicies:                   ratelimit.New(),
		maxContactsPerReg:            maxContactsPerReg,
		keyPolicy:                    keyPolicy,
		maxNames:                     maxNames,
		forceCNFromSAN:               forceCNFromSAN,
		reuseValidAuthz:              reuseValidAuthz,
		regByIPStats:                 stats.NewScope("RateLimit", "RegistrationsByIP"),
		regByIPRangeStats:            stats.NewScope("RateLimit", "RegistrationsByIPRange"),
		pendAuthByRegIDStats:         stats.NewScope("RateLimit", "PendingAuthorizationsByRegID"),
		pendOrdersByRegIDStats:       stats.NewScope("RateLimit", "PendingOrdersByRegID"),
		newOrderByRegIDStats:         stats.NewScope("RateLimit", "NewOrdersByRegID"),
		certsForDomainStats:          stats.NewScope("RateLimit", "CertificatesForDomain"),
		publisher:                    pubc,
		caa:                          caaClient,
		orderLifetime:                orderLifetime,
		ctpolicy:                     ctp,
		ctpolicyResults:              ctpolicyResults,
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
	ra.log.Errf("error reloading rate limit policy: %s", err)
}

var (
	unparseableEmailError = berrors.InvalidEmailError("not a valid e-mail address")
	emptyDNSResponseError = berrors.InvalidEmailError(
		"empty DNS response validating email domain - no MX/A records")
	multipleAddressError = berrors.InvalidEmailError("more than one e-mail address")
)

func problemIsTimeout(err error) bool {
	if dnsErr, ok := err.(*bdns.DNSError); ok && dnsErr.Timeout() {
		return true
	}

	return false
}

// forbiddenMailDomains is a map of domain names we do not allow after the
// @ symbol in contact mailto addresses. These are frequently used when
// copy-pasting example configurations and would not result in expiration
// messages and subscriber communications reaching the user that created the
// registration if allowed.
var forbiddenMailDomains = map[string]bool{
	// https://tools.ietf.org/html/rfc2606#section-3
	"example.com": true,
	"example.net": true,
	"example.org": true,
}

func validateEmail(ctx context.Context, address string, resolver bdns.DNSClient) error {
	email, err := mail.ParseAddress(address)
	if err != nil {
		return unparseableEmailError
	}
	splitEmail := strings.SplitN(email.Address, "@", -1)
	domain := strings.ToLower(splitEmail[len(splitEmail)-1])
	if forbiddenMailDomains[domain] {
		return berrors.InvalidEmailError(
			"invalid contact domain. Contact emails @%s are forbidden",
			domain)
	}
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

	// We treat timeouts as non-failures for best-effort email validation
	// See: https://github.com/letsencrypt/boulder/issues/2260
	if problemIsTimeout(errMX) || problemIsTimeout(errA) {
		return nil
	}

	if errMX != nil {
		return berrors.InvalidEmailError(errMX.Error())
	} else if len(resultMX) > 0 {
		return nil
	}
	if errA != nil {
		return berrors.InvalidEmailError(errA.Error())
	} else if len(resultA) > 0 {
		return nil
	}

	return emptyDNSResponseError
}

// certificateRequestAuthz is a struct for holding information about a valid
// authz referenced during a certificateRequestEvent. It holds both the
// authorization ID and the challenge type that made the authorization valid. We
// specifically include the challenge type that solved the authorization to make
// some common analysis easier.
type certificateRequestAuthz struct {
	ID            string
	ChallengeType string
}

// certificateRequestEvent is a struct for holding information that is logged as
// JSON to the audit log as the result of an issuance event.
type certificateRequestEvent struct {
	ID string `json:",omitempty"`
	// Requester is the associated account ID
	Requester int64 `json:",omitempty"`
	// OrderID is the associated order ID (may be empty for an ACME v1 issuance)
	OrderID int64 `json:",omitempty"`
	// SerialNumber is the string representation of the issued certificate's
	// serial number
	SerialNumber string `json:",omitempty"`
	// VerifiedFields are required by the baseline requirements and are always
	// a static value for Boulder.
	VerifiedFields []string `json:",omitempty"`
	// CommonName is the subject common name from the issued cert
	CommonName string `json:",omitempty"`
	// Names are the DNS SAN entries from the issued cert
	Names []string `json:",omitempty"`
	// NotBefore is the starting timestamp of the issued cert's validity period
	NotBefore time.Time `json:",omitempty"`
	// NotAfter is the ending timestamp of the issued cert's validity period
	NotAfter time.Time `json:",omitempty"`
	// RequestTime and ResponseTime are for tracking elapsed time during issuance
	RequestTime  time.Time `json:",omitempty"`
	ResponseTime time.Time `json:",omitempty"`
	// Error contains any encountered errors
	Error string `json:",omitempty"`
	// Authorizations is a map of identifier names to certificateRequestAuthz
	// objects. It can be used to understand how the names in a certificate
	// request were authorized.
	Authorizations map[string]certificateRequestAuthz
}

// noRegistrationID is used for the regID parameter to GetThreshold when no
// registration-based overrides are necessary.
const noRegistrationID = -1

// registrationCounter is a type to abstract the use of
// ra.SA.CountRegistrationsByIP or ra.SA.CountRegistrationsByIPRange
type registrationCounter func(context.Context, net.IP, time.Time, time.Time) (int, error)

// checkRegistrationIPLimit checks a specific registraton limit by using the
// provided registrationCounter function to determine if the limit has been
// exceeded for a given IP or IP range
func (ra *RegistrationAuthorityImpl) checkRegistrationIPLimit(
	ctx context.Context,
	limit ratelimit.RateLimitPolicy,
	ip net.IP,
	counter registrationCounter) error {

	if !limit.Enabled() {
		return nil
	}

	now := ra.clk.Now()
	windowBegin := limit.WindowBegin(now)
	count, err := counter(ctx, ip, windowBegin, now)
	if err != nil {
		return err
	}

	if count >= limit.GetThreshold(ip.String(), noRegistrationID) {
		return berrors.RateLimitError("too many registrations for this IP")
	}

	return nil
}

// checkRegistrationLimits enforces the RegistrationsPerIP and
// RegistrationsPerIPRange limits
func (ra *RegistrationAuthorityImpl) checkRegistrationLimits(ctx context.Context, ip net.IP) error {
	// Check the registrations per IP limit using the CountRegistrationsByIP SA
	// function that matches IP addresses exactly
	exactRegLimit := ra.rlPolicies.RegistrationsPerIP()
	err := ra.checkRegistrationIPLimit(ctx, exactRegLimit, ip, ra.SA.CountRegistrationsByIP)
	if err != nil {
		ra.regByIPStats.Inc("Exceeded", 1)
		ra.log.Infof("Rate limit exceeded, RegistrationsByIP, IP: %s", ip)
		return err
	}
	ra.regByIPStats.Inc("Pass", 1)

	// We only apply the fuzzy reg limit to IPv6 addresses.
	// Per https://golang.org/pkg/net/#IP.To4 "If ip is not an IPv4 address, To4
	// returns nil"
	if ip.To4() != nil {
		return nil
	}

	// Check the registrations per IP range limit using the
	// CountRegistrationsByIPRange SA function that fuzzy-matches IPv6 addresses
	// within a larger address range
	fuzzyRegLimit := ra.rlPolicies.RegistrationsPerIPRange()
	err = ra.checkRegistrationIPLimit(ctx, fuzzyRegLimit, ip, ra.SA.CountRegistrationsByIPRange)
	if err != nil {
		ra.regByIPRangeStats.Inc("Exceeded", 1)
		ra.log.Infof("Rate limit exceeded, RegistrationsByIPRange, IP: %s", ip)
		// For the fuzzyRegLimit we use a new error message that specifically
		// mentions that the limit being exceeded is applied to a *range* of IPs
		return berrors.RateLimitError("too many registrations for this IP range")
	}
	ra.regByIPRangeStats.Inc("Pass", 1)

	return nil
}

// NewRegistration constructs a new Registration from a request.
func (ra *RegistrationAuthorityImpl) NewRegistration(ctx context.Context, init core.Registration) (core.Registration, error) {
	if err := ra.keyPolicy.GoodKey(init.Key.Key); err != nil {
		return core.Registration{}, berrors.MalformedError("invalid public key: %s", err.Error())
	}
	if err := ra.checkRegistrationLimits(ctx, init.InitialIP); err != nil {
		return core.Registration{}, err
	}

	reg := core.Registration{
		Key:    init.Key,
		Status: core.StatusValid,
	}
	_ = mergeUpdate(&reg, init)

	// This field isn't updatable by the end user, so it isn't copied by
	// MergeUpdate. But we need to fill it in for new registrations.
	reg.InitialIP = init.InitialIP

	if err := ra.validateContacts(ctx, reg.Contact); err != nil {
		return core.Registration{}, err
	}

	// Store the authorization object, then return it
	reg, err := ra.SA.NewRegistration(ctx, reg)
	if err != nil {
		return core.Registration{}, err
	}

	ra.stats.Inc("NewRegistrations", 1)
	return reg, nil
}

func (ra *RegistrationAuthorityImpl) validateContacts(ctx context.Context, contacts *[]string) error {
	if contacts == nil || len(*contacts) == 0 {
		return nil // Nothing to validate
	}
	if ra.maxContactsPerReg > 0 && len(*contacts) > ra.maxContactsPerReg {
		return berrors.MalformedError(
			"too many contacts provided: %d > %d",
			len(*contacts),
			ra.maxContactsPerReg,
		)
	}

	for _, contact := range *contacts {
		if contact == "" {
			return berrors.MalformedError("empty contact")
		}
		parsed, err := url.Parse(contact)
		if err != nil {
			return berrors.MalformedError("invalid contact")
		}
		if parsed.Scheme != "mailto" {
			return berrors.MalformedError("contact method %s is not supported", parsed.Scheme)
		}
		if !core.IsASCII(contact) {
			return berrors.MalformedError(
				"contact email [%s] contains non-ASCII characters",
				contact,
			)
		}

		start := ra.clk.Now()
		ra.stats.Inc("ValidateEmail.Calls", 1)
		err = validateEmail(ctx, parsed.Opaque, ra.DNSClient)
		ra.stats.TimingDuration("ValidateEmail.Latency", ra.clk.Now().Sub(start))
		if err != nil {
			ra.stats.Inc("ValidateEmail.Errors", 1)
			return err
		}
		ra.stats.Inc("ValidateEmail.Successes", 1)
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
			ra.log.Infof("Rate limit exceeded, PendingAuthorizationsByRegID, regID: %d", regID)
			return berrors.RateLimitError("too many currently pending authorizations")
		}
		ra.pendAuthByRegIDStats.Inc("Pass", 1)
	}
	return nil
}

func (ra *RegistrationAuthorityImpl) checkInvalidAuthorizationLimit(ctx context.Context, regID int64, hostname string) error {
	limit := ra.rlPolicies.InvalidAuthorizationsPerAccount()
	// The SA.CountInvalidAuthorizations method is not implemented on the wrapper
	// interface, because we want to move towards using gRPC interfaces more
	// directly. So we type-assert the wrapper to a gRPC-specific type.
	saGRPC, ok := ra.SA.(*bgrpc.StorageAuthorityClientWrapper)
	if !limit.Enabled() || !ok {
		return nil
	}
	latest := ra.clk.Now().Add(ra.pendingAuthorizationLifetime)
	earliest := latest.Add(-limit.Window.Duration)
	latestNanos := latest.UnixNano()
	earliestNanos := earliest.UnixNano()
	count, err := saGRPC.CountInvalidAuthorizations(ctx, &sapb.CountInvalidAuthorizationsRequest{
		RegistrationID: &regID,
		Hostname:       &hostname,
		Range: &sapb.Range{
			Earliest: &earliestNanos,
			Latest:   &latestNanos,
		},
	})
	if err != nil {
		return err
	}
	if count == nil {
		return fmt.Errorf("nil count")
	}
	// Most rate limits have a key for overrides, but there is no meaningful key
	// here.
	noKey := ""
	if *count.Count >= int64(limit.GetThreshold(noKey, regID)) {
		ra.log.Infof("Rate limit exceeded, InvalidAuthorizationsByRegID, regID: %d", regID)
		return berrors.RateLimitError("too many failed authorizations recently")
	}
	return nil
}

// checkNewOrdersPerAccountLimit enforces the rlPolicies `NewOrdersPerAccount`
// rate limit. This rate limit ensures a client can not create more than the
// specified threshold of new orders within the specified time window.
func (ra *RegistrationAuthorityImpl) checkNewOrdersPerAccountLimit(ctx context.Context, acctID int64) error {
	limit := ra.rlPolicies.NewOrdersPerAccount()
	if !limit.Enabled() {
		return nil
	}
	latest := ra.clk.Now()
	earliest := latest.Add(-limit.Window.Duration)
	count, err := ra.SA.CountOrders(ctx, acctID, earliest, latest)
	if err != nil {
		return err
	}
	// There is no meaningful override key to use for this rate limit
	noKey := ""
	if count >= limit.GetThreshold(noKey, acctID) {
		ra.newOrderByRegIDStats.Inc("Exceeded", 1)
		return berrors.RateLimitError("too many new orders recently")
	}
	ra.newOrderByRegIDStats.Inc("Pass", 1)
	return nil
}

// NewAuthorization constructs a new Authz from a request. Values (domains) in
// request.Identifier will be lowercased before storage.
func (ra *RegistrationAuthorityImpl) NewAuthorization(ctx context.Context, request core.Authorization, regID int64) (core.Authorization, error) {
	identifier := request.Identifier
	identifier.Value = strings.ToLower(identifier.Value)

	// Check that the identifier is present and appropriate
	if err := ra.PA.WillingToIssue(identifier); err != nil {
		return core.Authorization{}, err
	}

	if err := ra.checkPendingAuthorizationLimit(ctx, regID); err != nil {
		return core.Authorization{}, err
	}

	if err := ra.checkInvalidAuthorizationLimit(ctx, regID, identifier.Value); err != nil {
		return core.Authorization{}, err
	}

	if ra.reuseValidAuthz {
		auths, err := ra.SA.GetValidAuthorizations(ctx, regID, []string{identifier.Value}, ra.clk.Now())
		if err != nil {
			outErr := berrors.InternalServerError(
				"unable to get existing validations for regID: %d, identifier: %s, %s",
				regID,
				identifier.Value,
				err,
			)
			ra.log.Warning(outErr.Error())
			return core.Authorization{}, outErr
		}

		if existingAuthz, ok := auths[identifier.Value]; ok {
			// Use the valid existing authorization's ID to find a fully populated version
			// The results from `GetValidAuthorizations` are most notably missing
			// `Challenge` values that the client expects in the result.
			populatedAuthz, err := ra.SA.GetAuthorization(ctx, existingAuthz.ID)
			if err != nil {
				outErr := berrors.InternalServerError(
					"unable to get existing authorization for auth ID: %s",
					existingAuthz.ID,
				)
				ra.log.Warningf("%s: %s", outErr.Error(), existingAuthz.ID)
				return core.Authorization{}, outErr
			}
			if ra.authzValidChallengeEnabled(&populatedAuthz) {
				// The existing authorization must not expire within the next 24 hours for
				// it to be OK for reuse
				reuseCutOff := ra.clk.Now().Add(time.Hour * 24)
				if populatedAuthz.Expires.After(reuseCutOff) {
					ra.stats.Inc("ReusedValidAuthz", 1)
					return populatedAuthz, nil
				}
			}
		}
	}
	if features.Enabled(features.ReusePendingAuthz) {
		nowishNano := ra.clk.Now().Add(time.Hour).UnixNano()
		identifierTypeString := string(identifier.Type)
		pendingAuth, err := ra.SA.GetPendingAuthorization(ctx, &sapb.GetPendingAuthorizationRequest{
			RegistrationID:  &regID,
			IdentifierType:  &identifierTypeString,
			IdentifierValue: &identifier.Value,
			ValidUntil:      &nowishNano,
		})
		if err != nil && !berrors.Is(err, berrors.NotFound) {
			return core.Authorization{}, berrors.InternalServerError(
				"unable to get pending authorization for regID: %d, identifier: %s: %s",
				regID,
				identifier.Value,
				err)
		} else if err == nil {
			return *pendingAuth, nil
		}
		// Fall through to normal creation flow.
	}

	authzPB, err := ra.createPendingAuthz(ctx, regID, identifier)
	if err != nil {
		return core.Authorization{}, err
	}
	authz, err := bgrpc.PBToAuthz(authzPB)
	if err != nil {
		return core.Authorization{}, err
	}

	result, err := ra.SA.NewPendingAuthorization(ctx, authz)
	if err != nil {
		// berrors.InternalServerError since the user-data was validated before being
		// passed to the SA.
		err = berrors.InternalServerError("invalid authorization request: %s", err)
		return core.Authorization{}, err
	}

	return result, err
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
func (ra *RegistrationAuthorityImpl) MatchesCSR(parsedCertificate *x509.Certificate, csr *x509.CertificateRequest) error {
	// Check issued certificate matches what was expected from the CSR
	hostNames := make([]string, len(csr.DNSNames))
	copy(hostNames, csr.DNSNames)
	if len(csr.Subject.CommonName) > 0 {
		hostNames = append(hostNames, csr.Subject.CommonName)
	}
	hostNames = core.UniqueLowerNames(hostNames)

	if !core.KeyDigestEquals(parsedCertificate.PublicKey, csr.PublicKey) {
		return berrors.InternalServerError("generated certificate public key doesn't match CSR public key")
	}
	if !ra.forceCNFromSAN && len(csr.Subject.CommonName) > 0 &&
		parsedCertificate.Subject.CommonName != strings.ToLower(csr.Subject.CommonName) {
		return berrors.InternalServerError("generated certificate CommonName doesn't match CSR CommonName")
	}
	// Sort both slices of names before comparison.
	parsedNames := parsedCertificate.DNSNames
	sort.Strings(parsedNames)
	sort.Strings(hostNames)
	if !reflect.DeepEqual(parsedNames, hostNames) {
		return berrors.InternalServerError("generated certificate DNSNames don't match CSR DNSNames")
	}
	if !reflect.DeepEqual(parsedCertificate.IPAddresses, csr.IPAddresses) {
		return berrors.InternalServerError("generated certificate IPAddresses don't match CSR IPAddresses")
	}
	if !reflect.DeepEqual(parsedCertificate.EmailAddresses, csr.EmailAddresses) {
		return berrors.InternalServerError("generated certificate EmailAddresses don't match CSR EmailAddresses")
	}
	if len(parsedCertificate.Subject.Country) > 0 || len(parsedCertificate.Subject.Organization) > 0 ||
		len(parsedCertificate.Subject.OrganizationalUnit) > 0 || len(parsedCertificate.Subject.Locality) > 0 ||
		len(parsedCertificate.Subject.Province) > 0 || len(parsedCertificate.Subject.StreetAddress) > 0 ||
		len(parsedCertificate.Subject.PostalCode) > 0 {
		return berrors.InternalServerError("generated certificate Subject contains fields other than CommonName, or SerialNumber")
	}
	now := ra.clk.Now()
	if now.Sub(parsedCertificate.NotBefore) > time.Hour*24 {
		return berrors.InternalServerError("generated certificate is back dated %s", now.Sub(parsedCertificate.NotBefore))
	}
	if !parsedCertificate.BasicConstraintsValid {
		return berrors.InternalServerError("generated certificate doesn't have basic constraints set")
	}
	if parsedCertificate.IsCA {
		return berrors.InternalServerError("generated certificate can sign other certificates")
	}
	if !reflect.DeepEqual(parsedCertificate.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) {
		return berrors.InternalServerError("generated certificate doesn't have correct key usage extensions")
	}

	return nil
}

// checkOrderAuthorizations verifies that a provided set of names associated
// with a specific order and account has all of the required valid, unexpired
// authorizations to proceed with issuance. It is the ACME v2 equivalent of
// `checkAuthorizations`. It returns the authorizations that satisfied the set
// of names or it returns an error. If it returns an error, it will be of type
// BoulderError.
func (ra *RegistrationAuthorityImpl) checkOrderAuthorizations(
	ctx context.Context,
	names []string,
	acctID accountID,
	orderID orderID) (map[string]*core.Authorization, error) {
	acctIDInt := int64(acctID)
	orderIDInt := int64(orderID)
	// Get all of the valid authorizations for this account/order
	authzs, err := ra.SA.GetValidOrderAuthorizations(
		ctx,
		&sapb.GetValidOrderAuthorizationsRequest{
			Id:     &orderIDInt,
			AcctID: &acctIDInt,
		})
	if err != nil {
		return nil, berrors.InternalServerError("error in GetValidOrderAuthorizations: %s", err)
	}
	// Ensure the names from the CSR are free of duplicates & lowercased.
	names = core.UniqueLowerNames(names)
	// Check the authorizations to ensure validity for the names required.
	if err = ra.checkAuthorizationsCAA(ctx, names, authzs, acctIDInt, ra.clk.Now()); err != nil {
		return nil, err
	}

	return authzs, nil
}

// checkAuthorizations checks that each requested name has a valid authorization
// that won't expire before the certificate expires. It returns the
// authorizations that satisifed the set of names or it returns an error.
// If it returns an error, it will be of type BoulderError.
func (ra *RegistrationAuthorityImpl) checkAuthorizations(ctx context.Context, names []string, regID int64) (map[string]*core.Authorization, error) {
	now := ra.clk.Now()
	for i := range names {
		names[i] = strings.ToLower(names[i])
	}
	auths, err := ra.SA.GetValidAuthorizations(ctx, regID, names, now)
	if err != nil {
		return nil, berrors.InternalServerError("error in GetValidAuthorizations: %s", err)
	}

	if err = ra.checkAuthorizationsCAA(ctx, names, auths, regID, now); err != nil {
		return nil, err
	}

	return auths, nil
}

// checkAuthorizationsCAA implements the common logic of validating a set of
// authorizations against a set of names that is used by both
// `checkAuthorizations` and `checkOrderAuthorizations`. If required CAA will be
// rechecked for authorizations that are too old.
// If it returns an error, it will be of type BoulderError.
func (ra *RegistrationAuthorityImpl) checkAuthorizationsCAA(
	ctx context.Context,
	names []string,
	authzs map[string]*core.Authorization,
	regID int64,
	now time.Time) error {
	// badNames contains the names that were unauthorized
	var badNames []string
	// recheckAuthzs is a list of authorizations that must have their CAA records rechecked
	var recheckAuthzs []*core.Authorization
	// Per Baseline Requirements, CAA must be checked within 8 hours of issuance.
	// CAA is checked when an authorization is validated, so as long as that was
	// less than 8 hours ago, we're fine. If it was more than 8 hours ago
	// we have to recheck. Since we don't record the validation time for
	// authorizations, we instead look at the expiration time and subtract out the
	// expected authorization lifetime. Note: If we adjust the authorization
	// lifetime in the future we will need to tweak this correspondingly so it
	// works correctly during the switchover.
	caaRecheckTime := now.Add(ra.authorizationLifetime).Add(-8 * time.Hour)
	for _, name := range names {
		authz := authzs[name]
		if authz == nil {
			badNames = append(badNames, name)
		} else if authz.Expires == nil {
			return berrors.InternalServerError("found an authorization with a nil Expires field: id %s", authz.ID)
		} else if authz.Expires.Before(now) {
			badNames = append(badNames, name)
		} else if authz.Expires.Before(caaRecheckTime) {
			// Ensure that CAA is rechecked for this name
			recheckAuthzs = append(recheckAuthzs, authz)
		}
	}

	if len(recheckAuthzs) > 0 {
		if err := ra.recheckCAA(ctx, recheckAuthzs); err != nil {
			return err
		}
	}

	if len(badNames) > 0 {
		return berrors.UnauthorizedError(
			"authorizations for these names not found or expired: %s",
			strings.Join(badNames, ", "),
		)
	}

	return nil
}

// recheckCAA accepts a list of of names that need to have their CAA records
// rechecked because their associated authorizations are sufficiently old and
// performs the CAA checks required for each. If any of the rechecks fail an
// error is returned.
func (ra *RegistrationAuthorityImpl) recheckCAA(ctx context.Context, authzs []*core.Authorization) error {
	ra.stats.Inc("recheck_caa", 1)
	ra.stats.Inc("recheck_caa_authzs", int64(len(authzs)))
	ch := make(chan error, len(authzs))
	for _, authz := range authzs {
		go func(authz *core.Authorization) {
			name := authz.Identifier.Value

			// If an authorization has multiple valid challenges,
			// the type of the first valid challenge is used for
			// the purposes of CAA rechecking.
			var method string
			for _, challenge := range authz.Challenges {
				if challenge.Status == core.StatusValid {
					method = challenge.Type
					break
				}
			}
			if method == "" {
				ch <- berrors.InternalServerError(
					"Internal error determining validation method for authorization ID %v (%v)",
					authz.ID, name,
				)
				return
			}

			resp, err := ra.caa.IsCAAValid(ctx, &vaPB.IsCAAValidRequest{
				Domain:           &name,
				ValidationMethod: &method,
			})
			if err != nil {
				ra.log.AuditErrf("Rechecking CAA: %s", err)
				err = berrors.InternalServerError(
					"Internal error rechecking CAA for authorization ID %v (%v)",
					authz.ID, name,
				)
			} else if resp.Problem != nil {
				err = berrors.CAAError(*resp.Problem.Detail)
			}
			ch <- err
		}(authz)
	}
	var caaFailures []string
	for _ = range authzs {
		if err := <-ch; berrors.Is(err, berrors.CAA) {
			caaFailures = append(caaFailures, err.Error())
		} else if err != nil {
			return err
		}
	}
	if len(caaFailures) > 0 {
		return berrors.CAAError("Rechecking CAA: %v", strings.Join(caaFailures, ", "))
	}
	return nil
}

// failOrder marks an order as failed by setting the problem details field of
// the order & persisting it through the SA. If an error occurs doing this we
// log it and return the order as-is. There aren't any alternatives if we can't
// add the error to the order.
func (ra *RegistrationAuthorityImpl) failOrder(
	ctx context.Context,
	order *corepb.Order,
	prob *probs.ProblemDetails) *corepb.Order {

	// Convert the problem to a protobuf problem for the *corepb.Order field
	pbProb, err := bgrpc.ProblemDetailsToPB(prob)
	if err != nil {
		ra.log.AuditErrf("Could not convert order error problem to PB: %q", err)
		return order
	}

	// Assign the protobuf problem to the field and save it via the SA
	order.Error = pbProb
	if err := ra.SA.SetOrderError(ctx, order); err != nil {
		ra.log.AuditErrf("Could not persist order error: %q", err)
	}
	return order
}

// FinalizeOrder accepts a request to finalize an order object and, if possible,
// issues a certificate to satisfy the order. If an order does not have valid,
// unexpired authorizations for all of its associated names an error is
// returned. Similarly we vet that all of the names in the order are acceptable
// based on current policy and return an error if the order can't be fulfilled.
// If successful the order will be returned in processing status for the client
// to poll while awaiting finalization to occur.
func (ra *RegistrationAuthorityImpl) FinalizeOrder(ctx context.Context, req *rapb.FinalizeOrderRequest) (*corepb.Order, error) {
	order := req.Order

	// Prior to ACME draft-10 the "ready" status did not exist and orders in
	// a pending status with valid authzs were finalizable. We accept both states
	// here for deployability ease. In the future we will only allow ready orders
	// to be finalized.
	// TODO(@cpu): Forbid finalizing "Pending" orders once
	// `features.Enabled(features.OrderReadyStatus)` is deployed
	if *order.Status != string(core.StatusPending) &&
		*order.Status != string(core.StatusReady) {
		return nil, berrors.MalformedError(
			"Order's status (%q) is not acceptable for finalization",
			*order.Status)
	}

	// There should never be an order with 0 names at the stage the RA is
	// processing the order but we check to be on the safe side, throwing an
	// internal server error if this assumption is ever violated.
	if len(order.Names) == 0 {
		return nil, berrors.InternalServerError("Order has no associated names")
	}

	// Parse the CSR from the request
	csrOb, err := x509.ParseCertificateRequest(req.Csr)
	if err != nil {
		return nil, err
	}

	if err := csrlib.VerifyCSR(csrOb, ra.maxNames, &ra.keyPolicy, ra.PA, ra.forceCNFromSAN, *req.Order.RegistrationID); err != nil {
		return nil, berrors.MalformedError(err.Error())
	}

	// Dedupe, lowercase and sort both the names from the CSR and the names in the
	// order.
	csrNames := core.UniqueLowerNames(csrOb.DNSNames)
	orderNames := core.UniqueLowerNames(order.Names)

	// Immediately reject the request if the number of names differ
	if len(orderNames) != len(csrNames) {
		return nil, berrors.UnauthorizedError("Order includes different number of names than CSR specifies")
	}

	// Check that the order names and the CSR names are an exact match
	for i, name := range orderNames {
		if name != csrNames[i] {
			return nil, berrors.UnauthorizedError("CSR is missing Order domain %q", name)
		}
	}

	// Update the order to be status processing - we issue synchronously at the
	// present time so this is somewhat artificial/unnecessary but allows planning
	// for the future.
	//
	// NOTE(@cpu): After this point any errors that are encountered must update
	// the state of the order to invalid by setting the order's error field.
	// Otherwise the order will be "stuck" in processing state. It can not be
	// finalized because it isn't pending, but we aren't going to process it
	// further because we already did and encountered an error.
	if err := ra.SA.SetOrderProcessing(ctx, order); err != nil {
		// Fail the order with a server internal error - we weren't able to set the
		// status to processing and that's unexpected & weird.
		ra.failOrder(ctx, order, probs.ServerInternal("Error setting order processing"))
		return nil, err
	}

	// Attempt issuance for the order. If the order isn't fully authorized this
	// will return an error.
	issueReq := core.CertificateRequest{
		Bytes: req.Csr,
		CSR:   csrOb,
	}
	cert, err := ra.issueCertificate(ctx, issueReq, accountID(*order.RegistrationID), orderID(*order.Id))
	if err != nil {
		// Fail the order. The problem is computed using
		// `web.ProblemDetailsForError`, the same function the WFE uses to convert
		// between `berrors` and problems. This will turn normal expected berrors like
		// berrors.UnauthorizedError into the correct
		// `urn:ietf:params:acme:error:unauthorized` problem while not letting
		// anything like a server internal error through with sensitive info.
		ra.failOrder(ctx, order, web.ProblemDetailsForError(err, "Error finalizing order"))
		return nil, err
	}

	// Parse the issued certificate to get the serial
	parsedCertificate, err := x509.ParseCertificate([]byte(cert.DER))
	if err != nil {
		// Fail the order with a server internal error. The certificate we failed
		// to parse was from our own CA. Bad news!
		ra.failOrder(ctx, order, probs.ServerInternal("Error parsing certificate DER"))
		return nil, err
	}
	serial := core.SerialToString(parsedCertificate.SerialNumber)

	// Finalize the order with its new CertificateSerial
	order.CertificateSerial = &serial
	if err := ra.SA.FinalizeOrder(ctx, order); err != nil {
		// Fail the order with a server internal error. We weren't able to persist
		// the certificate serial and that's unexpected & weird.
		ra.failOrder(ctx, order, probs.ServerInternal("Error persisting finalized order"))
		return nil, err
	}

	// Update the order status locally since the SA doesn't return the updated
	// order itself after setting the status
	validStatus := string(core.StatusValid)
	order.Status = &validStatus
	return order, nil
}

// NewCertificate requests the issuance of a certificate.
func (ra *RegistrationAuthorityImpl) NewCertificate(ctx context.Context, req core.CertificateRequest, regID int64) (core.Certificate, error) {
	// Verify the CSR
	if err := csrlib.VerifyCSR(req.CSR, ra.maxNames, &ra.keyPolicy, ra.PA, ra.forceCNFromSAN, regID); err != nil {
		return core.Certificate{}, berrors.MalformedError(err.Error())
	}
	// NewCertificate provides an order ID of 0, indicating this is a classic ACME
	// v1 issuance request from the new certificate endpoint that is not
	// associated with an ACME v2 order.
	return ra.issueCertificate(ctx, req, accountID(regID), orderID(0))
}

// To help minimize the chance that an accountID would be used as an order ID
// (or vice versa) when calling `issueCertificate` we define internal
// `accountID` and `orderID` types so that callers must explicitly cast.
type accountID int64
type orderID int64

// issueCertificate sets up a log event structure and captures any errors
// encountered during issuance, then calls issueCertificateInner.
func (ra *RegistrationAuthorityImpl) issueCertificate(
	ctx context.Context,
	req core.CertificateRequest,
	acctID accountID,
	oID orderID) (core.Certificate, error) {
	// Construct the log event
	logEvent := certificateRequestEvent{
		ID:          core.NewToken(),
		OrderID:     int64(oID),
		Requester:   int64(acctID),
		RequestTime: ra.clk.Now(),
	}
	var result string
	cert, err := ra.issueCertificateInner(ctx, req, acctID, oID, &logEvent)
	if err != nil {
		logEvent.Error = err.Error()
		result = "error"
	} else {
		issuanceExpvar.Set(ra.clk.Now().Unix())
		result = "successful"
	}
	logEvent.ResponseTime = ra.clk.Now()
	ra.log.AuditObject(fmt.Sprintf("Certificate request - %s", result), logEvent)
	return cert, err
}

// issueCertificateInner handles the common aspects of certificate issuance used by
// both the "classic" NewCertificate endpoint (for ACME v1) and the
// FinalizeOrder endpoint (for ACME v2).
func (ra *RegistrationAuthorityImpl) issueCertificateInner(
	ctx context.Context,
	req core.CertificateRequest,
	acctID accountID,
	oID orderID,
	logEvent *certificateRequestEvent) (core.Certificate, error) {
	emptyCert := core.Certificate{}
	if acctID <= 0 {
		return emptyCert, berrors.MalformedError("invalid account ID: %d", acctID)
	}

	// OrderID can be 0 if `issueCertificate` is called by `NewCertificate` for
	// the classic issuance flow. It should never be less than 0.
	if oID < 0 {
		return emptyCert, berrors.MalformedError("invalid order ID: %d", oID)
	}

	account, err := ra.SA.GetRegistration(ctx, int64(acctID))
	if err != nil {
		return emptyCert, err
	}

	csr := req.CSR
	logEvent.CommonName = csr.Subject.CommonName
	logEvent.Names = csr.DNSNames

	// Validate that authorization key is authorized for all domains in the CSR
	names := make([]string, len(csr.DNSNames))
	copy(names, csr.DNSNames)

	if core.KeyDigestEquals(csr.PublicKey, account.Key) {
		return emptyCert, berrors.MalformedError("certificate public key must be different than account key")
	}

	// Check rate limits before checking authorizations. If someone is unable to
	// issue a cert due to rate limiting, we don't want to tell them to go get the
	// necessary authorizations, only to later fail the rate limit check.
	err = ra.checkLimits(ctx, names, account.ID)
	if err != nil {
		return emptyCert, err
	}

	var authzs map[string]*core.Authorization
	// If the orderID is 0 then this is a classic issuance and we need to check
	// that the account is authorized for the names in the CSR.
	if oID == 0 {
		authzs, err = ra.checkAuthorizations(ctx, names, account.ID)
	} else {
		// Otherwise, if the orderID is not 0 we need to follow the order based
		// issuance process and check that this specific order is fully authorized
		// and associated with the expected account ID
		authzs, err = ra.checkOrderAuthorizations(ctx, names, acctID, oID)
	}
	if err != nil {
		// Pass through the error without wrapping it because the called functions
		// return BoulderError and we don't want to lose the type.
		return emptyCert, err
	}

	// Collect up a certificateRequestAuthz that stores the ID and challenge type
	// of each of the valid authorizations we used for this issuance.
	logEventAuthzs := make(map[string]certificateRequestAuthz, len(names))
	for name, authz := range authzs {
		var solvedByChallengeType string
		// If the authz has no solved by challenge type there has been an internal
		// consistency violation worth logging a warning about. In this case the
		// solvedByChallengeType will be logged as the emtpy string.
		if solvedByChallengeType = authz.SolvedBy(); solvedByChallengeType == "" {
			ra.log.Warningf("Authz %q has status %q but empty SolvedBy()", authz.ID, authz.Status)
		}
		logEventAuthzs[name] = certificateRequestAuthz{
			ID:            authz.ID,
			ChallengeType: solvedByChallengeType,
		}
	}
	logEvent.Authorizations = logEventAuthzs

	// Mark that we verified the CN and SANs
	logEvent.VerifiedFields = []string{"subject.commonName", "subjectAltName"}

	// Create the certificate and log the result
	acctIDInt := int64(acctID)
	orderIDInt := int64(oID)
	issueReq := &caPB.IssueCertificateRequest{
		Csr:            csr.Raw,
		RegistrationID: &acctIDInt,
		OrderID:        &orderIDInt,
	}

	// wrapError adds a prefix to an error. If the error is a boulder error then
	// the problem detail is updated with the prefix. Otherwise a new error is
	// returned with the message prefixed using `fmt.Errorf`
	wrapError := func(e error, prefix string) error {
		if berr, ok := e.(*berrors.BoulderError); ok {
			berr.Detail = fmt.Sprintf("%s: %s", prefix, berr.Detail)
			return berr
		}
		return fmt.Errorf("%s: %s", prefix, e)
	}

	var cert core.Certificate
	if features.Enabled(features.EmbedSCTs) {
		precert, err := ra.CA.IssuePrecertificate(ctx, issueReq)
		if err != nil {
			return emptyCert, wrapError(err, "issuing precertificate")
		}
		scts, err := ra.getSCTs(ctx, precert.DER)
		if err != nil {
			return emptyCert, wrapError(err, "getting SCTs")
		}
		cert, err = ra.CA.IssueCertificateForPrecertificate(ctx, &caPB.IssueCertificateForPrecertificateRequest{
			DER:            precert.DER,
			SCTs:           scts,
			RegistrationID: &acctIDInt,
			OrderID:        &orderIDInt,
		})
		if err != nil {
			return emptyCert, wrapError(err, "issuing certificate for precertificate")
		}
		// Asynchronously submit the final certificate to any configured logs
		go ra.ctpolicy.SubmitFinalCert(cert.DER)
	} else {
		cert, err = ra.CA.IssueCertificate(ctx, issueReq)
		if err != nil {
			return emptyCert, wrapError(err, "issuing certificate")
		}

		_, _ = ra.getSCTs(ctx, cert.DER)
	}

	parsedCertificate, err := x509.ParseCertificate([]byte(cert.DER))
	if err != nil {
		// berrors.InternalServerError because the certificate from the CA should be
		// parseable.
		return emptyCert, berrors.InternalServerError("failed to parse certificate: %s", err.Error())
	}

	err = ra.MatchesCSR(parsedCertificate, csr)
	if err != nil {
		return emptyCert, err
	}

	logEvent.SerialNumber = core.SerialToString(parsedCertificate.SerialNumber)
	logEvent.CommonName = parsedCertificate.Subject.CommonName
	logEvent.NotBefore = parsedCertificate.NotBefore
	logEvent.NotAfter = parsedCertificate.NotAfter

	ra.stats.Inc("NewCertificates", 1)
	return cert, nil
}

func (ra *RegistrationAuthorityImpl) getSCTs(ctx context.Context, cert []byte) (core.SCTDERs, error) {
	started := ra.clk.Now()
	scts, err := ra.ctpolicy.GetSCTs(ctx, cert)
	took := ra.clk.Since(started)
	// The final cert has already been issued so actually return it to the
	// user even if this fails since we aren't actually doing anything with
	// the SCTs yet.
	if err != nil {
		state := "failure"
		if err == context.DeadlineExceeded {
			state = "deadlineExceeded"
			// Convert the error to a missingSCTsError to communicate the timeout,
			// otherwise it will be a generic serverInternalError
			err = berrors.MissingSCTsError(err.Error())
		}
		ra.log.Warningf("ctpolicy.GetSCTs failed: %s", err)
		ra.ctpolicyResults.With(prometheus.Labels{"result": state}).Observe(took.Seconds())
		return nil, err
	}
	ra.ctpolicyResults.With(prometheus.Labels{"result": "success"}).Observe(took.Seconds())
	return scts, nil
}

// domainsForRateLimiting transforms a list of FQDNs into a list of eTLD+1's
// for the purpose of rate limiting. It also de-duplicates the output
// domains. Exact public suffix matches are not included.
func domainsForRateLimiting(names []string) ([]string, error) {
	var domains []string
	for _, name := range names {
		domain, err := publicsuffix.Domain(name)
		if err != nil {
			// The only possible errors are:
			// (1) publicsuffix.Domain is giving garbage values
			// (2) the public suffix is the domain itself
			// We assume 2 and do not include it in the result.
			continue
		}
		domains = append(domains, domain)
	}
	return core.UniqueLowerNames(domains), nil
}

// suffixesForRateLimiting returns the unique subset of input names that are
// exactly equal to a public suffix.
func suffixesForRateLimiting(names []string) ([]string, error) {
	var suffixMatches []string
	for _, name := range names {
		_, err := publicsuffix.Domain(name)
		if err != nil {
			// Like `domainsForRateLimiting`, the only possible errors here are:
			// (1) publicsuffix.Domain is giving garbage values
			// (2) the public suffix is the domain itself
			// We assume 2 and collect it into the result
			suffixMatches = append(suffixMatches, name)
		}
	}
	return core.UniqueLowerNames(suffixMatches), nil
}

// certCountRPC abstracts the choice of the SA.CountCertificatesByExactNames or
// the SA.CountCertificatesByNames RPC.
type certCountRPC func(ctx context.Context, names []string, earliest, lastest time.Time) ([]*sapb.CountByNames_MapElement, error)

// enforceNameCounts uses the provided count RPC to find a count of certificates
// for each of the names. If the count for any of the names exceeds the limit
// for the given registration then the names out of policy are returned to be
// used for a rate limit error.
func (ra *RegistrationAuthorityImpl) enforceNameCounts(
	ctx context.Context,
	names []string,
	limit ratelimit.RateLimitPolicy,
	regID int64,
	countFunc certCountRPC) ([]string, error) {

	now := ra.clk.Now()
	windowBegin := limit.WindowBegin(now)
	counts, err := countFunc(ctx, names, windowBegin, now)
	if err != nil {
		return nil, err
	}

	var badNames []string
	for _, entry := range counts {
		// Should not happen, but be defensive.
		if entry.Count == nil || entry.Name == nil {
			return nil, fmt.Errorf("CountByNames_MapElement had nil Count or Name")
		}
		if int(*entry.Count) >= limit.GetThreshold(*entry.Name, regID) {
			badNames = append(badNames, *entry.Name)
		}
	}
	return badNames, nil
}

func (ra *RegistrationAuthorityImpl) checkCertificatesPerNameLimit(ctx context.Context, names []string, limit ratelimit.RateLimitPolicy, regID int64) error {
	tldNames, err := domainsForRateLimiting(names)
	if err != nil {
		return err
	}
	exactPublicSuffixes, err := suffixesForRateLimiting(names)
	if err != nil {
		return err
	}

	var badNames []string
	// Domains that are exactly equal to a public suffix are treated differently
	// by enforcing the limit against only exact matches to the names, not
	// matches to subdomains as well. This allows the owners of such domains to
	// issue certificates even though issuance from their subdomains may
	// constantly exceed the rate limit.
	if len(exactPublicSuffixes) > 0 {
		psNamesOutOfLimit, err := ra.enforceNameCounts(ctx, exactPublicSuffixes, limit, regID, ra.SA.CountCertificatesByExactNames)
		if err != nil {
			return fmt.Errorf("checking certificates per name limit (exact) for %q: %s",
				names, err)
		}
		badNames = append(badNames, psNamesOutOfLimit...)
	}

	// If there are any tldNames, enforce the certificate count rate limit against
	// them and any subdomains.
	if len(tldNames) > 0 {
		namesOutOfLimit, err := ra.enforceNameCounts(ctx, tldNames, limit, regID, ra.SA.CountCertificatesByNames)
		if err != nil {
			return fmt.Errorf("checking certificates per name limit for %q: %s",
				names, err)
		}
		badNames = append(badNames, namesOutOfLimit...)
	}

	if len(badNames) > 0 {
		// check if there is already a existing certificate for
		// the exact name set we are issuing for. If so bypass the
		// the certificatesPerName limit.
		exists, err := ra.SA.FQDNSetExists(ctx, names)
		if err != nil {
			return fmt.Errorf("checking renewal exemption for %q: %s", names, err)
		}
		if exists {
			ra.certsForDomainStats.Inc("FQDNSetBypass", 1)
			return nil
		}
		domains := strings.Join(badNames, ", ")
		ra.certsForDomainStats.Inc("Exceeded", 1)
		ra.log.Infof("Rate limit exceeded, CertificatesForDomain, regID: %d, domains: %s", regID, domains)
		return berrors.RateLimitError(
			"too many certificates already issued for: %s",
			domains,
		)
	}
	ra.certsForDomainStats.Inc("Pass", 1)

	return nil
}

func (ra *RegistrationAuthorityImpl) checkCertificatesPerFQDNSetLimit(ctx context.Context, names []string, limit ratelimit.RateLimitPolicy, regID int64) error {
	count, err := ra.SA.CountFQDNSets(ctx, limit.Window.Duration, names)
	if err != nil {
		return fmt.Errorf("checking duplicate certificate limit for %q: %s", names, err)
	}
	names = core.UniqueLowerNames(names)
	if int(count) >= limit.GetThreshold(strings.Join(names, ","), regID) {
		return berrors.RateLimitError(
			"too many certificates already issued for exact set of domains: %s",
			strings.Join(names, ","),
		)
	}
	return nil
}

func (ra *RegistrationAuthorityImpl) checkLimits(ctx context.Context, names []string, regID int64) error {
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

// UpdateRegistration updates an existing Registration with new values. Caller
// is responsible for making sure that update.Key is only different from base.Key
// if it is being called from the WFE key change endpoint.
func (ra *RegistrationAuthorityImpl) UpdateRegistration(ctx context.Context, base core.Registration, update core.Registration) (core.Registration, error) {
	if changed := mergeUpdate(&base, update); !changed {
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
		// berrors.InternalServerError since the user-data was validated before being
		// passed to the SA.
		err = berrors.InternalServerError("Could not update registration: %s", err)
		return core.Registration{}, err
	}

	ra.stats.Inc("UpdatedRegistrations", 1)
	return base, nil
}

func contactsEqual(r *core.Registration, other core.Registration) bool {
	// If there is no existing contact slice, or the contact slice lengths
	// differ, then the other contact is not equal
	if r.Contact == nil || len(*other.Contact) != len(*r.Contact) {
		return false
	}

	// If there is an existing contact slice and it has the same length as the
	// new contact slice we need to look at each contact to determine if there
	// is a change being made. Use `sort.Strings` here to ensure a consistent
	// comparison
	a := *other.Contact
	b := *r.Contact
	sort.Strings(a)
	sort.Strings(b)
	for i := 0; i < len(a); i++ {
		// If the contact's string representation differs at any index they aren't
		// equal
		if a[i] != b[i] {
			return false
		}
	}

	// They are equal!
	return true
}

// MergeUpdate copies a subset of information from the input Registration
// into the Registration r. It returns true if an update was performed and the base object
// was changed, and false if no change was made.
func mergeUpdate(r *core.Registration, input core.Registration) bool {
	var changed bool

	// Note: we allow input.Contact to overwrite r.Contact even if the former is
	// empty in order to allow users to remove the contact associated with
	// a registration. Since the field type is a pointer to slice of pointers we
	// can perform a nil check to differentiate between an empty value and a nil
	// (e.g. not provided) value
	if input.Contact != nil && !contactsEqual(r, input) {
		r.Contact = input.Contact
		changed = true
	}

	// If there is an agreement in the input and it's not the same as the base,
	// then we update the base
	if len(input.Agreement) > 0 && input.Agreement != r.Agreement {
		r.Agreement = input.Agreement
		changed = true
	}

	if input.Key != nil {
		if r.Key != nil {
			sameKey, _ := core.PublicKeysEqual(r.Key.Key, input.Key.Key)
			if !sameKey {
				r.Key = input.Key
				changed = true
			}
		}
	}

	return changed
}

// UpdateAuthorization updates an authorization with new values.
func (ra *RegistrationAuthorityImpl) UpdateAuthorization(
	ctx context.Context,
	base core.Authorization,
	challengeIndex int,
	response core.Challenge) (core.Authorization, error) {
	// Refuse to update expired authorizations
	if base.Expires == nil || base.Expires.Before(ra.clk.Now()) {
		return core.Authorization{}, berrors.MalformedError("expired authorization")
	}

	authz := base
	if challengeIndex >= len(authz.Challenges) {
		return core.Authorization{}, berrors.MalformedError("invalid challenge index '%d'", challengeIndex)
	}

	ch := &authz.Challenges[challengeIndex]

	if response.Type != "" && ch.Type != response.Type {
		// TODO(riking): Check the rate on this, uncomment error return if negligible
		ra.stats.Inc("StartChallengeWrongType", 1)
		// return authz, berrors.MalformedError(
		// 	"invalid challenge update: provided type was %s but actual type is %s",
		// 	response.Type,
		// 	ch.Type,
		// )
	}

	// If TLSSNIRevalidation is enabled, find out whether this was a revalidation
	// (previous certificate existed) or not. If it is a revalidation, we can
	// proceed with validation even though the challenge type is currently
	// disabled.
	if !ra.PA.ChallengeTypeEnabled(ch.Type, authz.RegistrationID) && features.Enabled(features.TLSSNIRevalidation) {
		existsResp, err := ra.SA.PreviousCertificateExists(ctx, &sapb.PreviousCertificateExistsRequest{
			Domain: &authz.Identifier.Value,
			RegID:  &authz.RegistrationID,
		})
		if err != nil {
			return core.Authorization{}, err
		}
		if !*existsResp.Exists {
			return core.Authorization{}, berrors.MalformedError("challenge type %q no longer allowed", ch.Type)
		}
	}

	// When configured with `reuseValidAuthz` we can expect some clients to try
	// and update a challenge for an authorization that is already valid. In this
	// case we don't need to process the challenge update. It wouldn't be helpful,
	// the overall authorization is already good! We increment a stat for this
	// case and return early.
	if ra.reuseValidAuthz && authz.Status == core.StatusValid {
		ra.stats.Inc("ReusedValidAuthzChallenge", 1)
		return authz, nil
	}

	// Look up the account key for this authorization
	reg, err := ra.SA.GetRegistration(ctx, authz.RegistrationID)
	if err != nil {
		return core.Authorization{}, berrors.InternalServerError(err.Error())
	}

	// Compute the key authorization field based on the registration key
	expectedKeyAuthorization, err := ch.ExpectedKeyAuthorization(reg.Key)
	if err != nil {
		return core.Authorization{}, berrors.InternalServerError("could not compute expected key authorization value")
	}

	// NOTE(@cpu): Historically challenge update required the client to send
	// a JSON POST body that included a computed KeyAuthorization. The RA would
	// check this provided authorization against its own computation of the key
	// authorization and err if they did not match. New ACME specification does
	// not require this - the client does not need to send the key authorization.
	// To support this for ACMEv2 we only enforce the provided key authorization
	// matches expected if the update included it.
	if response.ProvidedKeyAuthorization != "" && expectedKeyAuthorization != response.ProvidedKeyAuthorization {
		return core.Authorization{}, berrors.MalformedError("provided key authorization was incorrect")
	}

	// Populate the ProvidedKeyAuthorization such that the VA can confirm the
	// expected vs actual without needing the registration key. Historically this
	// was done with the value from the challenge response and so the field name
	// is called "ProvidedKeyAuthorization", in reality this is just
	// "KeyAuthorization".
	// TODO(@cpu): Rename ProvidedKeyAuthorization to KeyAuthorization
	ch.ProvidedKeyAuthorization = expectedKeyAuthorization

	// Double check before sending to VA
	if cErr := ch.CheckConsistencyForValidation(); cErr != nil {
		return core.Authorization{}, berrors.MalformedError(cErr.Error())
	}

	// Store the updated version
	if err = ra.SA.UpdatePendingAuthorization(ctx, authz); err != nil {
		ra.log.Warningf("Error calling ra.SA.UpdatePendingAuthorization: %s", err)
		return core.Authorization{}, err
	}
	ra.stats.Inc("NewPendingAuthorizations", 1)

	// Dispatch to the VA for service

	vaCtx := context.Background()
	go func(authz core.Authorization) {
		// We will mutate challenges later in this goroutine to change status and
		// add error, but we also return a copy of authz immediately. To avoid a
		// data race, make a copy of the challenges slice here for mutation.
		challenges := make([]core.Challenge, len(authz.Challenges))
		copy(challenges, authz.Challenges)
		authz.Challenges = challenges

		records, err := ra.VA.PerformValidation(vaCtx, authz.Identifier.Value, authz.Challenges[challengeIndex], authz)
		var prob *probs.ProblemDetails
		if p, ok := err.(*probs.ProblemDetails); ok {
			prob = p
		} else if err != nil {
			prob = probs.ServerInternal("Could not communicate with VA")
			ra.log.AuditErrf("Could not communicate with VA: %s", err)
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
			ra.log.AuditErrf("Could not record updated validation: err=[%s] regID=[%d] authzID=[%s]",
				err, authz.RegistrationID, authz.ID)
		}
	}(authz)
	ra.stats.Inc("UpdatedPendingAuthorizations", 1)
	return authz, nil
}

func revokeEvent(state, serial, cn string, names []string, revocationCode revocation.Reason) string {
	return fmt.Sprintf(
		"Revocation - State: %s, Serial: %s, CN: %s, DNS Names: %s, Reason: %s",
		state,
		serial,
		cn,
		names,
		revocation.ReasonToString[revocationCode],
	)
}

// RevokeCertificateWithReg terminates trust in the certificate provided.
func (ra *RegistrationAuthorityImpl) RevokeCertificateWithReg(ctx context.Context, cert x509.Certificate, revocationCode revocation.Reason, regID int64) error {
	serialString := core.SerialToString(cert.SerialNumber)
	err := ra.SA.MarkCertificateRevoked(ctx, serialString, revocationCode)

	state := "Failure"
	defer func() {
		// Needed:
		//   Serial
		//   CN
		//   DNS names
		//   Revocation reason
		//   Registration ID of requester
		//   Error (if there was one)
		ra.log.AuditInfof("%s, Request by registration ID: %d",
			revokeEvent(state, serialString, cert.Subject.CommonName, cert.DNSNames, revocationCode),
			regID)
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
func (ra *RegistrationAuthorityImpl) AdministrativelyRevokeCertificate(ctx context.Context, cert x509.Certificate, revocationCode revocation.Reason, user string) error {
	serialString := core.SerialToString(cert.SerialNumber)
	err := ra.SA.MarkCertificateRevoked(ctx, serialString, revocationCode)

	state := "Failure"
	defer func() {
		// Needed:
		//   Serial
		//   CN
		//   DNS names
		//   Revocation reason
		//   Name of admin-revoker user
		//   Error (if there was one)
		ra.log.AuditInfof("%s, admin-revoker user: %s",
			revokeEvent(state, serialString, cert.Subject.CommonName, cert.DNSNames, revocationCode),
			user)
	}()

	if err != nil {
		state = fmt.Sprintf("Failure -- %s", err)
		return err
	}

	state = "Success"
	ra.stats.Inc("RevokedCertificates", 1)
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

	ra.stats.Inc("FinalizedAuthorizations", 1)
	return nil
}

// DeactivateRegistration deactivates a valid registration
func (ra *RegistrationAuthorityImpl) DeactivateRegistration(ctx context.Context, reg core.Registration) error {
	if reg.Status != core.StatusValid {
		return berrors.MalformedError("only valid registrations can be deactivated")
	}
	err := ra.SA.DeactivateRegistration(ctx, reg.ID)
	if err != nil {
		return berrors.InternalServerError(err.Error())
	}
	return nil
}

// DeactivateAuthorization deactivates a currently valid authorization
func (ra *RegistrationAuthorityImpl) DeactivateAuthorization(ctx context.Context, auth core.Authorization) error {
	if auth.Status != core.StatusValid && auth.Status != core.StatusPending {
		return berrors.MalformedError("only valid and pending authorizations can be deactivated")
	}
	err := ra.SA.DeactivateAuthorization(ctx, auth.ID)
	if err != nil {
		return berrors.InternalServerError(err.Error())
	}
	return nil
}

// NewOrder creates a new order object
func (ra *RegistrationAuthorityImpl) NewOrder(ctx context.Context, req *rapb.NewOrderRequest) (*corepb.Order, error) {
	order := &corepb.Order{
		RegistrationID: req.RegistrationID,
		Names:          core.UniqueLowerNames(req.Names),
	}

	// Validate that our policy allows issuing for each of the names in the order
	for _, name := range order.Names {
		id := core.AcmeIdentifier{Value: name, Type: core.IdentifierDNS}
		if features.Enabled(features.WildcardDomains) {
			if err := ra.PA.WillingToIssueWildcard(id); err != nil {
				return nil, err
			}
		} else if err := ra.PA.WillingToIssue(id); err != nil {
			return nil, err
		}
	}

	if features.Enabled(features.EnforceOverlappingWildcards) {
		if err := wildcardOverlap(order.Names); err != nil {
			return nil, err
		}
	}

	// See if there is an existing, pending, unexpired order that can be reused
	// for this account
	existingOrder, err := ra.SA.GetOrderForNames(ctx, &sapb.GetOrderForNamesRequest{
		AcctID: order.RegistrationID,
		Names:  order.Names,
	})
	// If there was an error and it wasn't an acceptable "NotFound" error, return
	// immediately
	if err != nil && !berrors.Is(err, berrors.NotFound) {
		return nil, err
	}
	// If there was an order, return it
	if existingOrder != nil {
		return existingOrder, nil
	}
	// Otherwise we were unable to find an order to reuse, continue creating a new
	// order

	// Check if there is rate limit space for a new order within the current window
	if err := ra.checkNewOrdersPerAccountLimit(ctx, *order.RegistrationID); err != nil {
		return nil, err
	}

	// An order's lifetime is effectively bound by the shortest remaining lifetime
	// of its associated authorizations. For that reason it would be Uncool if
	// `sa.GetAuthorizations` returned an authorization that was very close to
	// expiry. The resulting pending order that references it would itself end up
	// expiring very soon.
	// To prevent this we only return authorizations that are at least 1 day away
	// from expiring.
	authzExpiryCutoff := ra.clk.Now().AddDate(0, 0, 1).UnixNano()

	// We do not want any legacy V1 API authorizations not associated with an
	// order to be returned from the SA so we set requireV2Authzs to true
	requireV2Authzs := true
	existingAuthz, err := ra.SA.GetAuthorizations(ctx, &sapb.GetAuthorizationsRequest{
		RegistrationID:  order.RegistrationID,
		Now:             &authzExpiryCutoff,
		Domains:         order.Names,
		RequireV2Authzs: &requireV2Authzs,
	})
	if err != nil {
		return nil, err
	}

	// Collect up the authorizations we found into a map keyed by the domains the
	// authorizations correspond to
	nameToExistingAuthz := make(map[string]*corepb.Authorization, len(order.Names))
	for _, v := range existingAuthz.Authz {
		nameToExistingAuthz[*v.Domain] = v.Authz
	}

	// For each of the names in the order, if there is an acceptable
	// existing authz, append it to the order to reuse it. Otherwise track
	// that there is a missing authz for that name.
	var missingAuthzNames []string
	for _, name := range order.Names {
		// If there isn't an existing authz, note that its missing and continue
		if _, exists := nameToExistingAuthz[name]; !exists {
			missingAuthzNames = append(missingAuthzNames, name)
			continue
		}
		authz := nameToExistingAuthz[name]
		// If the identifier is a wildcard and the existing authz only has one
		// DNS-01 type challenge we can reuse it. In theory we will
		// never get back an authorization for a domain with a wildcard prefix
		// that doesn't meet this criteria from SA.GetAuthorizations but we verify
		// again to be safe.
		if strings.HasPrefix(name, "*.") &&
			len(authz.Challenges) == 1 && *authz.Challenges[0].Type == core.ChallengeTypeDNS01 {
			order.Authorizations = append(order.Authorizations, *authz.Id)
			continue
		} else if !strings.HasPrefix(name, "*.") {
			// If the identifier isn't a wildcard, we can reuse any authz
			order.Authorizations = append(order.Authorizations, *authz.Id)
			continue
		}

		// Delete the authz from the nameToExistingAuthz map since we are not reusing it.
		delete(nameToExistingAuthz, name)
		// If we reached this point then the existing authz was not acceptable for
		// reuse and we need to mark the name as requiring a new pending authz
		missingAuthzNames = append(missingAuthzNames, name)
	}

	// If the order isn't fully authorized we need to check that the client has
	// rate limit room for more pending authorizations
	if len(missingAuthzNames) > 0 {
		if err := ra.checkPendingAuthorizationLimit(ctx, *order.RegistrationID); err != nil {
			return nil, err
		}
	}

	// Loop through each of the names missing authzs and create a new pending
	// authorization for each.
	var newAuthzs []*corepb.Authorization
	for _, name := range missingAuthzNames {
		// TODO(#3069): Batch this check
		if err := ra.checkInvalidAuthorizationLimit(ctx, *order.RegistrationID, name); err != nil {
			return nil, err
		}
		pb, err := ra.createPendingAuthz(ctx, *order.RegistrationID, core.AcmeIdentifier{
			Type:  core.IdentifierDNS,
			Value: name,
		})
		if err != nil {
			return nil, err
		}
		newAuthzs = append(newAuthzs, pb)
	}

	// Start with the order's own expiry as the minExpiry. We only care
	// about authz expiries that are sooner than the order's expiry
	minExpiry := ra.clk.Now().Add(ra.orderLifetime)

	// Check the reused authorizations to see if any have an expiry before the
	// minExpiry (the order's lifetime)
	for _, authz := range nameToExistingAuthz {
		// An authz without an expiry is an unexpected internal server event
		if authz.Expires == nil {
			return nil, berrors.InternalServerError(
				"SA.GetAuthorizations returned an authz (%d) with nil expiry",
				*authz.Id)
		}
		// If the reused authorization expires before the minExpiry, it's expiry
		// is the new minExpiry.
		authzExpiry := time.Unix(0, *authz.Expires)
		if authzExpiry.Before(minExpiry) {
			minExpiry = authzExpiry
		}
	}

	// If new authorizations are needed, call AddPendingAuthorizations. Also check
	// whether the newly created pending authz's have an expiry lower than minExpiry
	if len(newAuthzs) > 0 {
		authzIDs, err := ra.SA.AddPendingAuthorizations(ctx, &sapb.AddPendingAuthorizationsRequest{Authz: newAuthzs})
		if err != nil {
			return nil, err
		}
		order.Authorizations = append(order.Authorizations, authzIDs.Ids...)

		// If the newly created pending authz's have an expiry closer than the
		// minExpiry the minExpiry is the pending authz expiry.
		newPendingAuthzExpires := ra.clk.Now().Add(ra.pendingAuthorizationLifetime)
		if newPendingAuthzExpires.Before(minExpiry) {
			minExpiry = newPendingAuthzExpires
		}
	}

	// Set the order's expiry to the minimum expiry
	minExpiryTS := minExpiry.UnixNano()
	order.Expires = &minExpiryTS
	storedOrder, err := ra.SA.NewOrder(ctx, order)
	if err != nil {
		return nil, err
	}

	return storedOrder, nil
}

// createPendingAuthz checks that a name is allowed for issuance and creates the
// necessary challenges for it and puts this and all of the relevant information
// into a corepb.Authorization for transmission to the SA to be stored
func (ra *RegistrationAuthorityImpl) createPendingAuthz(ctx context.Context, reg int64, identifier core.AcmeIdentifier) (*corepb.Authorization, error) {
	expires := ra.clk.Now().Add(ra.pendingAuthorizationLifetime).Truncate(time.Second).UnixNano()
	status := string(core.StatusPending)
	authz := &corepb.Authorization{
		Identifier:     &identifier.Value,
		RegistrationID: &reg,
		Status:         &status,
		Expires:        &expires,
	}

	if identifier.Type == core.IdentifierDNS && !features.Enabled(features.VAChecksGSB) {
		isSafeResp, err := ra.VA.IsSafeDomain(ctx, &vaPB.IsSafeDomainRequest{Domain: &identifier.Value})
		if err != nil {
			outErr := berrors.InternalServerError("unable to determine if domain was safe")
			ra.log.Warningf("%s: %s", outErr, err)
			return nil, outErr
		}
		if !isSafeResp.GetIsSafe() {
			return nil, berrors.UnauthorizedError(
				"%q was considered an unsafe domain by a third-party API",
				identifier.Value,
			)
		}
	}

	// If TLSSNIRevalidation is enabled, find out whether this was a revalidation
	// (previous certificate existed) or not. If it is a revalidation, we'll tell
	// the PA about that so it can include the TLS-SNI-01 challenge.
	var previousCertificateExists bool
	if features.Enabled(features.TLSSNIRevalidation) {
		existsResp, err := ra.SA.PreviousCertificateExists(ctx, &sapb.PreviousCertificateExistsRequest{
			Domain: &identifier.Value,
			RegID:  &reg,
		})
		if err != nil {
			return nil, err
		}
		previousCertificateExists = *existsResp.Exists
	}

	// Create challenges. The WFE will update them with URIs before sending them out.
	challenges, combinations, err := ra.PA.ChallengesFor(identifier, reg, previousCertificateExists)
	if err != nil {
		// The only time ChallengesFor errors it is a fatal configuration error
		// where challenges required by policy for an identifier are not enabled. We
		// want to treat this as an internal server error.
		return nil, berrors.InternalServerError(err.Error())
	}
	// Check each challenge for sanity.
	for _, challenge := range challenges {
		if err := challenge.CheckConsistencyForClientOffer(); err != nil {
			// berrors.InternalServerError because we generated these challenges, they should
			// be OK.
			err = berrors.InternalServerError("challenge didn't pass sanity check: %+v", challenge)
			return nil, err
		}
		challPB, err := bgrpc.ChallengeToPB(challenge)
		if err != nil {
			return nil, err
		}
		authz.Challenges = append(authz.Challenges, challPB)
	}
	comboBytes, err := json.Marshal(combinations)
	if err != nil {
		return nil, err
	}
	authz.Combinations = comboBytes
	return authz, nil
}

// authzValidChallengeEnabled checks whether the valid challenge in an authorization uses a type
// which is still enabled for given regID
func (ra *RegistrationAuthorityImpl) authzValidChallengeEnabled(authz *core.Authorization) bool {
	for _, chall := range authz.Challenges {
		if chall.Status == core.StatusValid {
			return ra.PA.ChallengeTypeEnabled(chall.Type, authz.RegistrationID)
		}
	}
	return false
}

// wildcardOverlap takes a slice of domain names and returns an error if any of
// them is a non-wildcard FQDN that overlaps with a wildcard domain in the map.
func wildcardOverlap(dnsNames []string) error {
	nameMap := make(map[string]bool, len(dnsNames))
	for _, v := range dnsNames {
		nameMap[v] = true
	}
	for name := range nameMap {
		if name[0] == '*' {
			continue
		}
		labels := strings.Split(name, ".")
		labels[0] = "*"
		if nameMap[strings.Join(labels, ".")] {
			return berrors.MalformedError(
				"Domain name %q is redundant with a wildcard domain in the same request. Remove one or the other from the certificate request.", name)
		}
	}
	return nil
}
