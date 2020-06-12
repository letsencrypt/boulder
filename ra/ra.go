package ra

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/akamai"
	akamaipb "github.com/letsencrypt/boulder/akamai/proto"
	caPB "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	csrlib "github.com/letsencrypt/boulder/csr"
	"github.com/letsencrypt/boulder/ctpolicy"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/identifier"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/probs"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/ratelimit"
	"github.com/letsencrypt/boulder/reloader"
	"github.com/letsencrypt/boulder/revocation"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	vaPB "github.com/letsencrypt/boulder/va/proto"
	"github.com/letsencrypt/boulder/web"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"golang.org/x/crypto/ocsp"
	grpc "google.golang.org/grpc"
)

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

	issuer *x509.Certificate
	purger akamaipb.AkamaiPurgerClient

	ctpolicy *ctpolicy.CTPolicy

	ctpolicyResults         *prometheus.HistogramVec
	rateLimitCounter        *prometheus.CounterVec
	namesPerCert            *prometheus.HistogramVec
	newRegCounter           prometheus.Counter
	reusedValidAuthzCounter prometheus.Counter
	recheckCAACounter       prometheus.Counter
	newCertCounter          prometheus.Counter
}

// NewRegistrationAuthorityImpl constructs a new RA object.
func NewRegistrationAuthorityImpl(
	clk clock.Clock,
	logger blog.Logger,
	stats prometheus.Registerer,
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
	purger akamaipb.AkamaiPurgerClient,
	issuer *x509.Certificate,
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

	namesPerCert := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "names_per_cert",
			Help: "Histogram of the number of SANs in requested and issued certificates",
			// The namesPerCert buckets are chosen based on the current Let's Encrypt
			// limit of 100 SANs per certificate.
			Buckets: []float64{1, 5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
		},
		// Type label value is either "requested" or "issued".
		[]string{"type"},
	)
	stats.MustRegister(namesPerCert)

	rateLimitCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ra_ratelimits",
		Help: "A counter of RA ratelimit checks labelled by type and pass/exceed",
	}, []string{"limit", "result"})
	stats.MustRegister(rateLimitCounter)

	newRegCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "new_registrations",
		Help: "A counter of new registrations",
	})
	stats.MustRegister(newRegCounter)

	reusedValidAuthzCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "reused_valid_authz",
		Help: "A counter of reused valid authorizations",
	})
	stats.MustRegister(reusedValidAuthzCounter)

	recheckCAACounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "recheck_caa",
		Help: "A counter of CAA rechecks",
	})
	stats.MustRegister(recheckCAACounter)

	newCertCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "new_certificates",
		Help: "A counter of new certificates",
	})
	stats.MustRegister(newCertCounter)

	ra := &RegistrationAuthorityImpl{
		clk:                          clk,
		log:                          logger,
		authorizationLifetime:        authorizationLifetime,
		pendingAuthorizationLifetime: pendingAuthorizationLifetime,
		rlPolicies:                   ratelimit.New(),
		maxContactsPerReg:            maxContactsPerReg,
		keyPolicy:                    keyPolicy,
		maxNames:                     maxNames,
		forceCNFromSAN:               forceCNFromSAN,
		reuseValidAuthz:              reuseValidAuthz,
		publisher:                    pubc,
		caa:                          caaClient,
		orderLifetime:                orderLifetime,
		ctpolicy:                     ctp,
		ctpolicyResults:              ctpolicyResults,
		purger:                       purger,
		issuer:                       issuer,
		namesPerCert:                 namesPerCert,
		rateLimitCounter:             rateLimitCounter,
		newRegCounter:                newRegCounter,
		reusedValidAuthzCounter:      reusedValidAuthzCounter,
		recheckCAACounter:            recheckCAACounter,
		newCertCounter:               newCertCounter,
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
		ra.rateLimitCounter.WithLabelValues("registrations_by_ip", "exceeded").Inc()
		ra.log.Infof("Rate limit exceeded, RegistrationsByIP, IP: %s", ip)
		return err
	}
	ra.rateLimitCounter.WithLabelValues("registrations_by_ip", "pass").Inc()

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
		ra.rateLimitCounter.WithLabelValues("registrations_by_ip_range", "exceeded").Inc()
		ra.log.Infof("Rate limit exceeded, RegistrationsByIPRange, IP: %s", ip)
		// For the fuzzyRegLimit we use a new error message that specifically
		// mentions that the limit being exceeded is applied to a *range* of IPs
		return berrors.RateLimitError("too many registrations for this IP range")
	}
	ra.rateLimitCounter.WithLabelValues("registrations_by_ip_range", "pass").Inc()

	return nil
}

// NewRegistration constructs a new Registration from a request.
func (ra *RegistrationAuthorityImpl) NewRegistration(ctx context.Context, init core.Registration) (core.Registration, error) {
	if err := ra.keyPolicy.GoodKey(ctx, init.Key.Key); err != nil {
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

	ra.newRegCounter.Inc()
	return reg, nil
}

// validateContacts checks the provided list of contacts, returning an error if
// any are not acceptable. Unacceptable contacts lists include:
// * An empty list
// * A list has more than maxContactsPerReg contacts
// * A list containing an empty contact
// * A list containing a contact that does not parse as a URL
// * A list containing a contact that has a URL scheme other than mailto
// * A list containing a mailto contact that contains hfields
// * A list containing a contact that has non-ascii characters
// * A list containing a contact that doesn't pass `policy.ValidEmail`
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
			return berrors.InvalidEmailError("empty contact")
		}
		parsed, err := url.Parse(contact)
		if err != nil {
			return berrors.InvalidEmailError("invalid contact")
		}
		if parsed.Scheme != "mailto" {
			return berrors.InvalidEmailError("contact method %q is not supported", parsed.Scheme)
		}
		if parsed.RawQuery != "" {
			return berrors.InvalidEmailError("contact email [%q] contains hfields", contact)
		}
		if !core.IsASCII(contact) {
			return berrors.InvalidEmailError(
				"contact email [%q] contains non-ASCII characters",
				contact,
			)
		}
		if err := policy.ValidEmail(parsed.Opaque); err != nil {
			return err
		}
	}

	// NOTE(@cpu): For historical reasons (</3) we store ACME account contact
	// information de-normalized in a fixed size `contact` field on the
	// `registrations` table. At the time of writing this field is VARCHAR(191)
	// That means the largest marshalled JSON value we can store is 191 bytes.
	const maxContactBytes = 191
	if jsonBytes, err := json.Marshal(*contacts); err != nil {
		// This shouldn't happen with a simple []string but if it does we want the
		// error to be logged internally but served as a 500 to the user so we
		// return a bare error and not a berror here.
		return fmt.Errorf("failed to marshal reg.Contact to JSON: %#v", *contacts)
	} else if len(jsonBytes) >= maxContactBytes {
		return berrors.InvalidEmailError(
			"too many/too long contact(s). Please use shorter or fewer email addresses")
	}

	return nil
}

func (ra *RegistrationAuthorityImpl) checkPendingAuthorizationLimit(ctx context.Context, regID int64) error {
	limit := ra.rlPolicies.PendingAuthorizationsPerAccount()
	if limit.Enabled() {
		countPB, err := ra.SA.CountPendingAuthorizations2(ctx, &sapb.RegistrationID{
			Id: &regID,
		})
		if err != nil {
			return err
		}
		// Most rate limits have a key for overrides, but there is no meaningful key
		// here.
		noKey := ""
		if int(*countPB.Count) >= limit.GetThreshold(noKey, regID) {
			ra.rateLimitCounter.WithLabelValues("pending_authorizations_by_registration_id", "exceeded").Inc()
			ra.log.Infof("Rate limit exceeded, PendingAuthorizationsByRegID, regID: %d", regID)
			return berrors.RateLimitError("too many currently pending authorizations")
		}
		ra.rateLimitCounter.WithLabelValues("pending_authorizations_by_registration_id", "pass").Inc()
	}
	return nil
}

// checkInvalidAuthorizationLimits checks the failed validation limit for each
// of the provided hostnames. It returns the first error.
func (ra *RegistrationAuthorityImpl) checkInvalidAuthorizationLimits(ctx context.Context, regID int64, hostnames []string) error {
	results := make(chan error, len(hostnames))
	for _, hostname := range hostnames {
		go func(hostname string) {
			results <- ra.checkInvalidAuthorizationLimit(ctx, regID, hostname)
		}(hostname)
	}
	// We don't have to wait for all of the goroutines to finish because there's
	// enough capacity in the chan for them all to write their result even if
	// nothing is reading off the chan anymore.
	for i := 0; i < len(hostnames); i++ {
		if err := <-results; err != nil {
			return err
		}
	}
	return nil
}

func (ra *RegistrationAuthorityImpl) checkInvalidAuthorizationLimit(ctx context.Context, regID int64, hostname string) error {
	limit := ra.rlPolicies.InvalidAuthorizationsPerAccount()
	if !limit.Enabled() {
		return nil
	}
	latest := ra.clk.Now().Add(ra.pendingAuthorizationLifetime)
	earliest := latest.Add(-limit.Window.Duration)
	latestNanos := latest.UnixNano()
	earliestNanos := earliest.UnixNano()
	req := &sapb.CountInvalidAuthorizationsRequest{
		RegistrationID: &regID,
		Hostname:       &hostname,
		Range: &sapb.Range{
			Earliest: &earliestNanos,
			Latest:   &latestNanos,
		},
	}
	count, err := ra.SA.CountInvalidAuthorizations2(ctx, req)
	if err != nil {
		return err
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
		ra.rateLimitCounter.WithLabelValues("new_order_by_registration_id", "exceeded").Inc()
		return berrors.RateLimitError("too many new orders recently")
	}
	ra.rateLimitCounter.WithLabelValues("new_order_by_registration_id", "pass").Inc()
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
		now := ra.clk.Now().UnixNano()
		authzMapPB, err := ra.SA.GetValidAuthorizations2(ctx, &sapb.GetValidAuthorizationsRequest{
			RegistrationID: &regID,
			Domains:        []string{identifier.Value},
			Now:            &now,
		})
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
		auths, err := bgrpc.PBToAuthzMap(authzMapPB)
		if err != nil {
			return core.Authorization{}, err
		}

		if existingAuthz, ok := auths[identifier.Value]; ok {
			if ra.authzValidChallengeEnabled(existingAuthz) {
				// The existing authorization must not expire within the next 24 hours for
				// it to be OK for reuse
				reuseCutOff := ra.clk.Now().Add(time.Hour * 24)
				if existingAuthz.Expires.After(reuseCutOff) {
					ra.reusedValidAuthzCounter.Inc()
					return *existingAuthz, nil
				}
			}
		}
	}

	nowishNano := ra.clk.Now().Add(time.Hour).UnixNano()
	identifierTypeString := string(identifier.Type)
	req := &sapb.GetPendingAuthorizationRequest{
		RegistrationID:  &regID,
		IdentifierType:  &identifierTypeString,
		IdentifierValue: &identifier.Value,
		ValidUntil:      &nowishNano,
	}
	pendingPB, err := ra.SA.GetPendingAuthorization2(ctx, req)
	if err != nil && !berrors.Is(err, berrors.NotFound) {
		return core.Authorization{}, berrors.InternalServerError(
			"unable to get pending authorization for regID: %d, identifier: %s: %s",
			regID,
			identifier.Value,
			err)
	} else if err == nil {
		return bgrpc.PBToAuthz(pendingPB)
	}

	if features.Enabled(features.V1DisableNewValidations) {
		exists, err := ra.SA.PreviousCertificateExists(ctx, &sapb.PreviousCertificateExistsRequest{
			Domain: &identifier.Value,
			RegID:  &regID,
		})
		if err != nil {
			return core.Authorization{}, err
		}
		if !*exists.Exists {
			return core.Authorization{}, berrors.UnauthorizedError("Validations for new domains are disabled in the V1 API (https://community.letsencrypt.org/t/end-of-life-plan-for-acmev1/88430)")
		}
	}

	authzPB, err := ra.createPendingAuthz(ctx, regID, identifier)
	if err != nil {
		return core.Authorization{}, err
	}

	authzIDs, err := ra.SA.NewAuthorizations2(ctx, &sapb.AddPendingAuthorizationsRequest{
		Authz: []*corepb.Authorization{authzPB},
	})
	if err != nil {
		return core.Authorization{}, err
	}
	if len(authzIDs.Ids) != 1 {
		return core.Authorization{}, berrors.InternalServerError("unexpected number of authorization IDs returned from NewAuthorizations2: expected 1, got %d", len(authzIDs.Ids))
	}
	// The current internal authorization objects use a string for the ID, the new
	// storage format uses a integer ID. In order to maintain compatibility we
	// convert the integer ID to a string.
	id := fmt.Sprintf("%d", authzIDs.Ids[0])
	authzPB.Id = &id
	return bgrpc.PBToAuthz(authzPB)
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
	req := &sapb.GetValidOrderAuthorizationsRequest{
		Id:     &orderIDInt,
		AcctID: &acctIDInt,
	}
	authzMapPB, err := ra.SA.GetValidOrderAuthorizations2(ctx, req)
	if err != nil {
		return nil, berrors.InternalServerError("error in GetValidOrderAuthorizations: %s", err)
	}
	authzs, err := bgrpc.PBToAuthzMap(authzMapPB)
	if err != nil {
		return nil, err
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
// authorizations that satisfied the set of names or it returns an error.
// If it returns an error, it will be of type BoulderError.
func (ra *RegistrationAuthorityImpl) checkAuthorizations(ctx context.Context, names []string, regID int64) (map[string]*core.Authorization, error) {
	now := ra.clk.Now()
	for i := range names {
		names[i] = strings.ToLower(names[i])
	}
	nowUnix := now.UnixNano()
	authMapPB, err := ra.SA.GetValidAuthorizations2(ctx, &sapb.GetValidAuthorizationsRequest{
		RegistrationID: &regID,
		Domains:        names,
		Now:            &nowUnix,
	})
	if err != nil {
		return nil, err
	}
	auths, err := bgrpc.PBToAuthzMap(authMapPB)
	if err != nil {
		return nil, err
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
	// less than 8 hours ago, we're fine. We recheck if that was more than 7 hours
	// ago, to be on the safe side. Since we don't record the validation time for
	// authorizations, we instead look at the expiration time and subtract out the
	// expected authorization lifetime. Note: If we adjust the authorization
	// lifetime in the future we will need to tweak this correspondingly so it
	// works correctly during the switchover.
	caaRecheckTime := now.Add(ra.authorizationLifetime).Add(-7 * time.Hour)
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
	ra.recheckCAACounter.Add(float64(len(authzs)))

	type authzCAAResult struct {
		authz *core.Authorization
		err   error
	}
	ch := make(chan authzCAAResult, len(authzs))
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
				ch <- authzCAAResult{
					authz: authz,
					err: berrors.InternalServerError(
						"Internal error determining validation method for authorization ID %v (%v)",
						authz.ID, name),
				}
				return
			}

			resp, err := ra.caa.IsCAAValid(ctx, &vaPB.IsCAAValidRequest{
				Domain:           &name,
				ValidationMethod: &method,
				AccountURIID:     &authz.RegistrationID,
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
			ch <- authzCAAResult{
				authz: authz,
				err:   err,
			}
		}(authz)
	}
	var subErrors []berrors.SubBoulderError
	// Read a recheckResult for each authz from the results channel
	for i := 0; i < len(authzs); i++ {
		recheckResult := <-ch
		// If the result had a CAA boulder error, construct a suberror with the
		// identifier from the authorization that was checked.
		if err := recheckResult.err; err != nil {
			if bErr, _ := err.(*berrors.BoulderError); berrors.Is(err, berrors.CAA) {
				subErrors = append(subErrors, berrors.SubBoulderError{
					Identifier:   recheckResult.authz.Identifier,
					BoulderError: bErr})
			} else {
				return err
			}
		}
	}
	if len(subErrors) > 0 {
		var detail string
		// If there was only one error, then use it as the top level error that is
		// returned.
		if len(subErrors) == 1 {
			return subErrors[0].BoulderError
		}
		detail = fmt.Sprintf(
			"Rechecking CAA for %q and %d more identifiers failed. "+
				"Refer to sub-problems for more information",
			subErrors[0].Identifier.Value,
			len(subErrors)-1)
		return (&berrors.BoulderError{
			Type:   berrors.CAA,
			Detail: detail,
		}).WithSubErrors(subErrors)
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

	if *order.Status != string(core.StatusReady) {
		return nil, berrors.OrderNotReadyError(
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

	if err := csrlib.VerifyCSR(ctx, csrOb, ra.maxNames, &ra.keyPolicy, ra.PA, ra.forceCNFromSAN, *req.Order.RegistrationID); err != nil {
		// VerifyCSR returns berror instances that can be passed through as-is
		// without wrapping.
		return nil, err
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

	// Note how many names were in this finalized certificate order.
	ra.namesPerCert.With(
		prometheus.Labels{"type": "issued"},
	).Observe(float64(len(order.Names)))

	// Update the order status locally since the SA doesn't return the updated
	// order itself after setting the status
	validStatus := string(core.StatusValid)
	order.Status = &validStatus
	return order, nil
}

// NewCertificate requests the issuance of a certificate.
func (ra *RegistrationAuthorityImpl) NewCertificate(ctx context.Context, req core.CertificateRequest, regID int64) (core.Certificate, error) {
	// Verify the CSR
	if err := csrlib.VerifyCSR(ctx, req.CSR, ra.maxNames, &ra.keyPolicy, ra.PA, ra.forceCNFromSAN, regID); err != nil {
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
		result = "successful"
	}
	logEvent.ResponseTime = ra.clk.Now()
	ra.log.AuditObject(fmt.Sprintf("Certificate request - %s", result), logEvent)
	return cert, err
}

// issueCertificateInner handles the common aspects of certificate issuance used by
// both the "classic" NewCertificate endpoint (for ACME v1) and the
// FinalizeOrder endpoint (for ACME v2).
//
// This function is responsible for ensuring that we never try to issue a final
// certificate twice for the same precertificate, because that has the potential
// to create certificates with duplicate serials. For instance, this could
// happen if final certificates were created with different sets of SCTs. This
// function accomplishes that by bailing on issuance if there is any error in
// IssueCertificateForPrecertificate; there are no retries, and serials are
// generated in IssuePrecertificate, so serials with errors are dropped and
// never have final certificates issued for them (because there is a possibility
// that the certificate was actually issued but there was an error returning
// it).
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
		// solvedByChallengeType will be logged as the empty string.
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

	precert, err := ra.CA.IssuePrecertificate(ctx, issueReq)
	if err != nil {
		return emptyCert, wrapError(err, "issuing precertificate")
	}
	parsedPrecert, err := x509.ParseCertificate(precert.DER)
	if err != nil {
		return emptyCert, wrapError(err, "parsing precertificate")
	}
	scts, err := ra.getSCTs(ctx, precert.DER, parsedPrecert.NotAfter)
	if err != nil {
		return emptyCert, wrapError(err, "getting SCTs")
	}
	cert, err := ra.CA.IssueCertificateForPrecertificate(ctx, &caPB.IssueCertificateForPrecertificateRequest{
		DER:            precert.DER,
		SCTs:           scts,
		RegistrationID: &acctIDInt,
		OrderID:        &orderIDInt,
	})
	if err != nil {
		return emptyCert, wrapError(err, "issuing certificate for precertificate")
	}

	parsedCertificate, err := x509.ParseCertificate([]byte(cert.DER))
	if err != nil {
		// berrors.InternalServerError because the certificate from the CA should be
		// parseable.
		return emptyCert, berrors.InternalServerError("failed to parse certificate: %s", err.Error())
	}

	// Asynchronously submit the final certificate to any configured logs
	go ra.ctpolicy.SubmitFinalCert(cert.DER, parsedCertificate.NotAfter)

	err = ra.MatchesCSR(parsedCertificate, csr)
	if err != nil {
		return emptyCert, err
	}

	logEvent.SerialNumber = core.SerialToString(parsedCertificate.SerialNumber)
	logEvent.CommonName = parsedCertificate.Subject.CommonName
	logEvent.NotBefore = parsedCertificate.NotBefore
	logEvent.NotAfter = parsedCertificate.NotAfter

	ra.newCertCounter.Inc()
	return cert, nil
}

func (ra *RegistrationAuthorityImpl) getSCTs(ctx context.Context, cert []byte, expiration time.Time) (core.SCTDERs, error) {
	started := ra.clk.Now()
	scts, err := ra.ctpolicy.GetSCTs(ctx, cert, expiration)
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
// domains. Exact public suffix matches are included.
func domainsForRateLimiting(names []string) ([]string, error) {
	var domains []string
	for _, name := range names {
		domain, err := publicsuffix.Domain(name)
		if err != nil {
			// The only possible errors are:
			// (1) publicsuffix.Domain is giving garbage values
			// (2) the public suffix is the domain itself
			// We assume 2 and include the original name in the result.
			domains = append(domains, name)
		} else {
			domains = append(domains, domain)
		}
	}
	return core.UniqueLowerNames(domains), nil
}

// enforceNameCounts uses the provided count RPC to find a count of certificates
// for each of the names. If the count for any of the names exceeds the limit
// for the given registration then the names out of policy are returned to be
// used for a rate limit error.
func (ra *RegistrationAuthorityImpl) enforceNameCounts(
	ctx context.Context,
	names []string,
	limit ratelimit.RateLimitPolicy,
	regID int64) ([]string, error) {

	now := ra.clk.Now()
	windowBegin := limit.WindowBegin(now)
	counts, err := ra.SA.CountCertificatesByNames(ctx, names, windowBegin, now)
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
	// check if there is already an existing certificate for
	// the exact name set we are issuing for. If so bypass the
	// the certificatesPerName limit.
	exists, err := ra.SA.FQDNSetExists(ctx, names)
	if err != nil {
		return fmt.Errorf("checking renewal exemption for %q: %s", names, err)
	}
	if exists {
		ra.rateLimitCounter.WithLabelValues("certificates_for_domain", "FQDN set bypass").Inc()
		return nil
	}

	tldNames, err := domainsForRateLimiting(names)
	if err != nil {
		return err
	}

	namesOutOfLimit, err := ra.enforceNameCounts(ctx, tldNames, limit, regID)
	if err != nil {
		return fmt.Errorf("checking certificates per name limit for %q: %s",
			names, err)
	}

	if len(namesOutOfLimit) > 0 {
		// check if there is already an existing certificate for
		// the exact name set we are issuing for. If so bypass the
		// the certificatesPerName limit.
		exists, err := ra.SA.FQDNSetExists(ctx, names)
		if err != nil {
			return fmt.Errorf("checking renewal exemption for %q: %s", names, err)
		}
		if exists {
			ra.rateLimitCounter.WithLabelValues("certificates_for_domain", "FQDN set bypass").Inc()
			return nil
		}

		ra.log.Infof("Rate limit exceeded, CertificatesForDomain, regID: %d, domains: %s", regID, strings.Join(namesOutOfLimit, ", "))
		ra.rateLimitCounter.WithLabelValues("certificates_for_domain", "exceeded").Inc()
		if len(namesOutOfLimit) > 1 {
			var subErrors []berrors.SubBoulderError
			for _, name := range namesOutOfLimit {
				subErrors = append(subErrors, berrors.SubBoulderError{
					Identifier:   identifier.DNSIdentifier(name),
					BoulderError: berrors.RateLimitError("too many certificates already issued").(*berrors.BoulderError),
				})
			}
			return berrors.RateLimitError("too many certificates already issued for multiple names (%s and %d others)", namesOutOfLimit[0], len(namesOutOfLimit)).(*berrors.BoulderError).WithSubErrors(subErrors)
		}
		return berrors.RateLimitError("too many certificates already issued for: %s", namesOutOfLimit[0])
	}
	ra.rateLimitCounter.WithLabelValues("certificates_for_domain", "pass").Inc()

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
		// done, we can return before calling ra.SA.UpdateRegistration since there's
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

// recordValidation records an authorization validation event,
// it should only be used on v2 style authorizations.
func (ra *RegistrationAuthorityImpl) recordValidation(ctx context.Context, authID string, authExpires *time.Time, challenge *core.Challenge) error {
	authzID, err := strconv.ParseInt(authID, 10, 64)
	if err != nil {
		return err
	}
	status := string(challenge.Status)
	var expires int64
	if challenge.Status == core.StatusInvalid {
		expires = authExpires.UnixNano()
	} else {
		expires = ra.clk.Now().Add(ra.authorizationLifetime).UnixNano()
	}
	vr, err := bgrpc.ValidationResultToPB(challenge.ValidationRecord, challenge.Error)
	if err != nil {
		return err
	}
	err = ra.SA.FinalizeAuthorization2(ctx, &sapb.FinalizeAuthorizationRequest{
		Id:                &authzID,
		Status:            &status,
		Expires:           &expires,
		Attempted:         &challenge.Type,
		ValidationRecords: vr.Records,
		ValidationError:   vr.Problems,
	})
	if err != nil {
		return err
	}
	return nil
}

// PerformValidation initiates validation for a specific challenge associated
// with the given base authorization. The authorization and challenge are
// updated based on the results.
func (ra *RegistrationAuthorityImpl) PerformValidation(
	ctx context.Context,
	req *rapb.PerformValidationRequest) (*corepb.Authorization, error) {
	base, err := bgrpc.PBToAuthz(req.Authz)
	if err != nil {
		return nil, err
	}

	// Refuse to update expired authorizations
	if base.Expires == nil || base.Expires.Before(ra.clk.Now()) {
		return nil, berrors.MalformedError("expired authorization")
	}

	authz := base
	challIndex := int(*req.ChallengeIndex)
	if challIndex >= len(authz.Challenges) {
		return nil,
			berrors.MalformedError("invalid challenge index '%d'", challIndex)
	}

	ch := &authz.Challenges[challIndex]

	// This challenge type may have been disabled since the challenge was created.
	if !ra.PA.ChallengeTypeEnabled(ch.Type) {
		return nil, berrors.MalformedError("challenge type %q no longer allowed", ch.Type)
	}

	// When configured with `reuseValidAuthz` we can expect some clients to try
	// and update a challenge for an authorization that is already valid. In this
	// case we don't need to process the challenge update. It wouldn't be helpful,
	// the overall authorization is already good! We increment a stat for this
	// case and return early.
	if ra.reuseValidAuthz && authz.Status == core.StatusValid {
		return req.Authz, nil
	}

	if authz.Status != core.StatusPending {
		return nil, berrors.WrongAuthorizationStateError("authorization must be pending")
	}

	// Look up the account key for this authorization
	reg, err := ra.SA.GetRegistration(ctx, authz.RegistrationID)
	if err != nil {
		return nil, berrors.InternalServerError(err.Error())
	}

	// Compute the key authorization field based on the registration key
	expectedKeyAuthorization, err := ch.ExpectedKeyAuthorization(reg.Key)
	if err != nil {
		return nil, berrors.InternalServerError("could not compute expected key authorization value")
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
		return nil, berrors.MalformedError(cErr.Error())
	}

	// Dispatch to the VA for service
	vaCtx := context.Background()
	go func(authz core.Authorization) {
		// We will mutate challenges later in this goroutine to change status and
		// add error, but we also return a copy of authz immediately. To avoid a
		// data race, make a copy of the challenges slice here for mutation.
		challenges := make([]core.Challenge, len(authz.Challenges))
		copy(challenges, authz.Challenges)
		authz.Challenges = challenges

		records, err := ra.VA.PerformValidation(vaCtx, authz.Identifier.Value, authz.Challenges[challIndex], authz)
		var prob *probs.ProblemDetails
		if p, ok := err.(*probs.ProblemDetails); ok {
			prob = p
		} else if err != nil {
			prob = probs.ServerInternal("Could not communicate with VA")
			ra.log.AuditErrf("Could not communicate with VA: %s", err)
		}

		// Save the updated records
		challenge := &authz.Challenges[challIndex]
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
		authz.Challenges[challIndex] = *challenge

		if err := ra.recordValidation(vaCtx, authz.ID, authz.Expires, challenge); err != nil {
			ra.log.AuditErrf("Could not record updated validation: err=[%s] regID=[%d] authzID=[%s]",
				err, authz.RegistrationID, authz.ID)
		}
	}(authz)
	return bgrpc.AuthzToPB(authz)
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

// revokeCertificate generates a revoked OCSP response for the given certificate, stores
// the revocation information, and purges OCSP request URLs from Akamai.
func (ra *RegistrationAuthorityImpl) revokeCertificate(ctx context.Context, cert x509.Certificate, code revocation.Reason, revokedBy int64, source string, comment string) error {
	status := string(core.OCSPStatusRevoked)
	reason := int32(code)
	revokedAt := ra.clk.Now().UnixNano()
	ocspResponse, err := ra.CA.GenerateOCSP(ctx, &caPB.GenerateOCSPRequest{
		CertDER:   cert.Raw,
		Status:    &status,
		Reason:    &reason,
		RevokedAt: &revokedAt,
	})
	if err != nil {
		return err
	}
	serial := core.SerialToString(cert.SerialNumber)
	// for some reason we use int32 and int64 for the reason in different
	// protobuf messages, so we have to re-cast it here.
	reason64 := int64(reason)
	err = ra.SA.RevokeCertificate(ctx, &sapb.RevokeCertificateRequest{
		Serial:   &serial,
		Reason:   &reason64,
		Date:     &revokedAt,
		Response: ocspResponse.Response,
	})
	if err != nil {
		return err
	}
	if features.Enabled(features.BlockedKeyTable) && reason == ocsp.KeyCompromise {
		digest, err := core.KeyDigest(cert.PublicKey)
		if err != nil {
			return err
		}
		req := &sapb.AddBlockedKeyRequest{
			KeyHash: digest[:],
			Added:   &revokedAt,
			Source:  &source,
		}
		if comment != "" {
			req.Comment = &comment
		}
		if features.Enabled(features.StoreRevokerInfo) && revokedBy != 0 {
			req.RevokedBy = &revokedBy
		}
		if _, err = ra.SA.AddBlockedKey(ctx, req); err != nil {
			return err
		}
	}
	purgeURLs, err := akamai.GeneratePurgeURLs(cert.Raw, ra.issuer)
	if err != nil {
		return err
	}
	_, err = ra.purger.Purge(ctx, &akamaipb.PurgeRequest{Urls: purgeURLs})
	if err != nil {
		return err
	}

	return nil
}

// RevokeCertificateWithReg terminates trust in the certificate provided.
func (ra *RegistrationAuthorityImpl) RevokeCertificateWithReg(ctx context.Context, cert x509.Certificate, revocationCode revocation.Reason, regID int64) error {
	serialString := core.SerialToString(cert.SerialNumber)
	err := ra.revokeCertificate(ctx, cert, revocationCode, regID, "API", "")

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
	// TODO(#4774): allow setting the comment via the RPC, format should be:
	// "revoked by %s: %s", user, comment
	err := ra.revokeCertificate(ctx, cert, revocationCode, 0, "admin-revoker", fmt.Sprintf("revoked by %s", user))

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
	authzID, err := strconv.ParseInt(auth.ID, 10, 64)
	if err != nil {
		return err
	}
	if _, err := ra.SA.DeactivateAuthorization2(ctx, &sapb.AuthorizationID2{Id: &authzID}); err != nil {
		return err
	}
	return nil
}

// checkOrderNames validates that the RA's policy authority allows issuing for
// each of the names in an order. If any of the names are unacceptable a
// malformed or rejectedIdentifier error with suberrors for each rejected
// identifier is returned.
func (ra *RegistrationAuthorityImpl) checkOrderNames(names []string) error {
	idents := make([]identifier.ACMEIdentifier, len(names))
	for i, name := range names {
		idents[i] = identifier.DNSIdentifier(name)
	}
	if err := ra.PA.WillingToIssueWildcards(idents); err != nil {
		return err
	}
	return nil
}

// NewOrder creates a new order object
func (ra *RegistrationAuthorityImpl) NewOrder(ctx context.Context, req *rapb.NewOrderRequest) (*corepb.Order, error) {
	order := &corepb.Order{
		RegistrationID: req.RegistrationID,
		Names:          core.UniqueLowerNames(req.Names),
	}

	if len(order.Names) > ra.maxNames {
		return nil, berrors.MalformedError(
			"Order cannot contain more than %d DNS names", ra.maxNames)
	}

	// Validate that our policy allows issuing for each of the names in the order
	if err := ra.checkOrderNames(order.Names); err != nil {
		return nil, err
	}

	if err := wildcardOverlap(order.Names); err != nil {
		return nil, err
	}

	// See if there is an existing unexpired pending (or ready) order that can be reused
	// for this account
	useV2Authzs := true
	existingOrder, err := ra.SA.GetOrderForNames(ctx, &sapb.GetOrderForNamesRequest{
		AcctID:              order.RegistrationID,
		Names:               order.Names,
		UseV2Authorizations: &useV2Authzs,
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

	// Check if there is rate limit space for a new order within the current window
	if err := ra.checkNewOrdersPerAccountLimit(ctx, *order.RegistrationID); err != nil {
		return nil, err
	}
	// Check if there is rate limit space for issuing a certificate for the new
	// order's names. If there isn't then it doesn't make sense to allow creating
	// an order - it will just fail when finalization checks the same limits.
	if err := ra.checkLimits(ctx, order.Names, *order.RegistrationID); err != nil {
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
	getAuthReq := &sapb.GetAuthorizationsRequest{
		RegistrationID:  order.RegistrationID,
		Now:             &authzExpiryCutoff,
		Domains:         order.Names,
		RequireV2Authzs: &requireV2Authzs,
	}
	existingAuthz, err := ra.SA.GetAuthorizations2(ctx, getAuthReq)
	if err != nil {
		return nil, err
	}

	// Collect up the authorizations we found into a map keyed by the domains the
	// authorizations correspond to
	nameToExistingAuthz := make(map[string]*corepb.Authorization, len(order.Names))
	for _, v := range existingAuthz.Authz {
		// Don't reuse a valid authorization if the reuseValidAuthz flag is
		// disabled.
		if *v.Authz.Status == string(core.StatusValid) && !ra.reuseValidAuthz {
			continue
		}
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
			authzID, err := strconv.ParseInt(*authz.Id, 10, 64)
			if err != nil {
				return nil, err
			}
			order.V2Authorizations = append(order.V2Authorizations, authzID)
			continue
		} else if !strings.HasPrefix(name, "*.") {
			// If the identifier isn't a wildcard, we can reuse any authz
			authzID, err := strconv.ParseInt(*authz.Id, 10, 64)
			if err != nil {
				return nil, err
			}
			order.V2Authorizations = append(order.V2Authorizations, authzID)
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
		if err := ra.checkInvalidAuthorizationLimits(ctx, *order.RegistrationID, missingAuthzNames); err != nil {
			return nil, err
		}
	}

	// Loop through each of the names missing authzs and create a new pending
	// authorization for each.
	var newAuthzs []*corepb.Authorization
	for _, name := range missingAuthzNames {
		pb, err := ra.createPendingAuthz(ctx, *order.RegistrationID, identifier.ACMEIdentifier{
			Type:  identifier.DNS,
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
				"SA.GetAuthorizations returned an authz (%s) with nil expiry",
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
		req := sapb.AddPendingAuthorizationsRequest{Authz: newAuthzs}
		authzIDs, err := ra.SA.NewAuthorizations2(ctx, &req)
		if err != nil {
			return nil, err
		}
		order.V2Authorizations = append(order.V2Authorizations, authzIDs.Ids...)
		// If the newly created pending authz's have an expiry closer than the
		// minExpiry the minExpiry is the pending authz expiry.
		newPendingAuthzExpires := ra.clk.Now().Add(ra.pendingAuthorizationLifetime)
		if newPendingAuthzExpires.Before(minExpiry) {
			minExpiry = newPendingAuthzExpires
		}
	}

	// Note how many names are being requested in this certificate order.
	ra.namesPerCert.With(
		prometheus.Labels{"type": "requested"},
	).Observe(float64(len(order.Names)))

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
func (ra *RegistrationAuthorityImpl) createPendingAuthz(ctx context.Context, reg int64, identifier identifier.ACMEIdentifier) (*corepb.Authorization, error) {
	expires := ra.clk.Now().Add(ra.pendingAuthorizationLifetime).Truncate(time.Second).UnixNano()
	status := string(core.StatusPending)
	authz := &corepb.Authorization{
		Identifier:     &identifier.Value,
		RegistrationID: &reg,
		Status:         &status,
		Expires:        &expires,
	}

	// Create challenges. The WFE will update them with URIs before sending them out.
	challenges, err := ra.PA.ChallengesFor(identifier)
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
	return authz, nil
}

// authzValidChallengeEnabled checks whether the valid challenge in an authorization uses a type
// which is still enabled for given regID
func (ra *RegistrationAuthorityImpl) authzValidChallengeEnabled(authz *core.Authorization) bool {
	for _, chall := range authz.Challenges {
		if chall.Status == core.StatusValid {
			return ra.PA.ChallengeTypeEnabled(chall.Type)
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
