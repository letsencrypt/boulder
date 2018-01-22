package ra

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	sagrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/probs"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/ratelimit"
	"github.com/letsencrypt/boulder/sa"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
	vaPB "github.com/letsencrypt/boulder/va/proto"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	jose "gopkg.in/square/go-jose.v2"
)

type DummyValidationAuthority struct {
	argument        chan core.Authorization
	RecordsReturn   []core.ValidationRecord
	ProblemReturn   *probs.ProblemDetails
	IsNotSafe       bool
	IsSafeDomainErr error
}

func (dva *DummyValidationAuthority) PerformValidation(ctx context.Context, domain string, challenge core.Challenge, authz core.Authorization) ([]core.ValidationRecord, error) {
	dva.argument <- authz
	return dva.RecordsReturn, dva.ProblemReturn
}

func (dva *DummyValidationAuthority) IsSafeDomain(ctx context.Context, req *vaPB.IsSafeDomainRequest) (*vaPB.IsDomainSafe, error) {
	if dva.IsSafeDomainErr != nil {
		return nil, dva.IsSafeDomainErr
	}
	ret := !dva.IsNotSafe
	return &vaPB.IsDomainSafe{IsSafe: &ret}, nil
}

var (
	SupportedChallenges = map[string]bool{
		core.ChallengeTypeHTTP01:   true,
		core.ChallengeTypeTLSSNI01: true,
		core.ChallengeTypeDNS01:    true,
	}

	// These values we simulate from the client
	AccountKeyJSONA = []byte(`{
		"kty":"RSA",
		"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":"AQAB"
	}`)
	AccountKeyA = jose.JSONWebKey{}

	AccountKeyJSONB = []byte(`{
		"kty":"RSA",
		"n":"z8bp-jPtHt4lKBqepeKF28g_QAEOuEsCIou6sZ9ndsQsEjxEOQxQ0xNOQezsKa63eogw8YS3vzjUcPP5BJuVzfPfGd5NVUdT-vSSwxk3wvk_jtNqhrpcoG0elRPQfMVsQWmxCAXCVRz3xbcFI8GTe-syynG3l-g1IzYIIZVNI6jdljCZML1HOMTTW4f7uJJ8mM-08oQCeHbr5ejK7O2yMSSYxW03zY-Tj1iVEebROeMv6IEEJNFSS4yM-hLpNAqVuQxFGetwtwjDMC1Drs1dTWrPuUAAjKGrP151z1_dE74M5evpAhZUmpKv1hY-x85DC6N0hFPgowsanmTNNiV75w",
		"e":"AQAB"
	}`)
	AccountKeyB = jose.JSONWebKey{}

	AccountKeyJSONC = []byte(`{
		"kty":"RSA",
		"n":"rFH5kUBZrlPj73epjJjyCxzVzZuV--JjKgapoqm9pOuOt20BUTdHqVfC2oDclqM7HFhkkX9OSJMTHgZ7WaVqZv9u1X2yjdx9oVmMLuspX7EytW_ZKDZSzL-sCOFCuQAuYKkLbsdcA3eHBK_lwc4zwdeHFMKIulNvLqckkqYB9s8GpgNXBDIQ8GjR5HuJke_WUNjYHSd8jY1LU9swKWsLQe2YoQUz_ekQvBvBCoaFEtrtRaSJKNLIVDObXFr2TLIiFiM0Em90kK01-eQ7ZiruZTKomll64bRFPoNo4_uwubddg3xTqur2vdF3NyhTrYdvAgTem4uC0PFjEQ1bK_djBQ",
		"e":"AQAB"
	}`)
	AccountKeyC = jose.JSONWebKey{}

	// These values we simulate from the client
	AccountPrivateKeyJSON = []byte(`{
		"kty":"RSA",
		"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":"AQAB",
		"d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
		"p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
		"q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
		"dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
		"dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
		"qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU"
	}`)
	AccountPrivateKey = jose.JSONWebKey{}

	ShortKeyJSON = []byte(`{
		"e": "AQAB",
		"kty": "RSA",
		"n": "tSwgy3ORGvc7YJI9B2qqkelZRUC6F1S5NwXFvM4w5-M0TsxbFsH5UH6adigV0jzsDJ5imAechcSoOhAh9POceCbPN1sTNwLpNbOLiQQ7RD5mY_"
		}`)

	ShortKey = jose.JSONWebKey{}

	AuthzRequest = core.Authorization{
		Identifier: core.AcmeIdentifier{
			Type:  core.IdentifierDNS,
			Value: "not-example.com",
		},
	}

	ResponseIndex = 0

	ExampleCSR = &x509.CertificateRequest{}

	// These values are populated by the tests as we go
	url0, _      = url.Parse("http://acme.invalid/authz/60p2Dc_XmUB2UUJBV4wYkF7BJbPD9KlDnUL3SmFMuTE?challenge=0")
	url1, _      = url.Parse("http://acme.invalid/authz/60p2Dc_XmUB2UUJBV4wYkF7BJbPD9KlDnUL3SmFMuTE?challenge=0")
	Registration = core.Registration{}
	AuthzInitial = core.Authorization{
		ID:             "60p2Dc_XmUB2UUJBV4wYkF7BJbPD9KlDnUL3SmFMuTE",
		Identifier:     core.AcmeIdentifier{Type: "dns", Value: "not-example.com"},
		RegistrationID: 1,
		Status:         "pending",
		Combinations:   [][]int{{0}, {1}},
	}
	AuthzFinal = core.Authorization{}

	log = blog.UseMock()
)

func makeResponse(ch core.Challenge) (out core.Challenge, err error) {
	keyAuthorization, err := ch.ExpectedKeyAuthorization(&AccountKeyA)
	if err != nil {
		return
	}

	out = core.Challenge{ProvidedKeyAuthorization: keyAuthorization}
	return
}

var testKeyPolicy = goodkey.KeyPolicy{
	AllowRSA:           true,
	AllowECDSANISTP256: true,
	AllowECDSANISTP384: true,
}

var ctx = context.Background()

// dummyRateLimitConfig satisfies the ratelimit.RateLimitConfig interface while
// allowing easy mocking of the individual RateLimitPolicy's
type dummyRateLimitConfig struct {
	TotalCertificatesPolicy               ratelimit.RateLimitPolicy
	CertificatesPerNamePolicy             ratelimit.RateLimitPolicy
	RegistrationsPerIPPolicy              ratelimit.RateLimitPolicy
	RegistrationsPerIPRangePolicy         ratelimit.RateLimitPolicy
	PendingAuthorizationsPerAccountPolicy ratelimit.RateLimitPolicy
	PendingOrdersPerAccountPolicy         ratelimit.RateLimitPolicy
	InvalidAuthorizationsPerAccountPolicy ratelimit.RateLimitPolicy
	CertificatesPerFQDNSetPolicy          ratelimit.RateLimitPolicy
}

func (r *dummyRateLimitConfig) TotalCertificates() ratelimit.RateLimitPolicy {
	return r.TotalCertificatesPolicy
}

func (r *dummyRateLimitConfig) CertificatesPerName() ratelimit.RateLimitPolicy {
	return r.CertificatesPerNamePolicy
}

func (r *dummyRateLimitConfig) RegistrationsPerIP() ratelimit.RateLimitPolicy {
	return r.RegistrationsPerIPPolicy
}

func (r *dummyRateLimitConfig) RegistrationsPerIPRange() ratelimit.RateLimitPolicy {
	return r.RegistrationsPerIPRangePolicy
}

func (r *dummyRateLimitConfig) PendingAuthorizationsPerAccount() ratelimit.RateLimitPolicy {
	return r.PendingAuthorizationsPerAccountPolicy
}

func (r *dummyRateLimitConfig) PendingOrdersPerAccount() ratelimit.RateLimitPolicy {
	return r.PendingOrdersPerAccountPolicy
}

func (r *dummyRateLimitConfig) InvalidAuthorizationsPerAccount() ratelimit.RateLimitPolicy {
	return r.InvalidAuthorizationsPerAccountPolicy
}

func (r *dummyRateLimitConfig) CertificatesPerFQDNSet() ratelimit.RateLimitPolicy {
	return r.CertificatesPerFQDNSetPolicy
}

func (r *dummyRateLimitConfig) LoadPolicies(contents []byte) error {
	return nil // NOP - unrequired behaviour for this mock
}

func initAuthorities(t *testing.T) (*DummyValidationAuthority, *sa.SQLStorageAuthority, *RegistrationAuthorityImpl, clock.FakeClock, func()) {
	err := json.Unmarshal(AccountKeyJSONA, &AccountKeyA)
	test.AssertNotError(t, err, "Failed to unmarshal public JWK")
	err = json.Unmarshal(AccountKeyJSONB, &AccountKeyB)
	test.AssertNotError(t, err, "Failed to unmarshal public JWK")
	err = json.Unmarshal(AccountKeyJSONC, &AccountKeyC)
	test.AssertNotError(t, err, "Failed to unmarshal public JWK")

	err = json.Unmarshal(AccountPrivateKeyJSON, &AccountPrivateKey)
	test.AssertNotError(t, err, "Failed to unmarshal private JWK")

	err = json.Unmarshal(ShortKeyJSON, &ShortKey)
	test.AssertNotError(t, err, "Failed to unmarshal JWK")

	fc := clock.NewFake()
	// Set to some non-zero time.
	fc.Set(time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC))

	dbMap, err := sa.NewDbMap(vars.DBConnSA, 0)
	if err != nil {
		t.Fatalf("Failed to create dbMap: %s", err)
	}
	ssa, err := sa.NewSQLStorageAuthority(dbMap, fc, log, metrics.NewNoopScope(), 1)
	if err != nil {
		t.Fatalf("Failed to create SA: %s", err)
	}

	saDBCleanUp := test.ResetSATestDatabase(t)

	va := &DummyValidationAuthority{argument: make(chan core.Authorization, 1)}

	pa, err := policy.New(SupportedChallenges)
	test.AssertNotError(t, err, "Couldn't create PA")
	err = pa.SetHostnamePolicyFile("../test/hostname-policy.json")
	test.AssertNotError(t, err, "Couldn't set hostname policy")

	stats := metrics.NewNoopScope()

	ca := &mocks.MockCA{
		PEM: eeCertPEM,
	}
	cleanUp := func() {
		saDBCleanUp()
	}

	block, _ := pem.Decode(CSRPEM)
	ExampleCSR, _ = x509.ParseCertificateRequest(block.Bytes)

	Registration, _ = ssa.NewRegistration(ctx, core.Registration{
		Key:       &AccountKeyA,
		InitialIP: net.ParseIP("3.2.3.3"),
		Status:    core.StatusValid,
	})

	ra := NewRegistrationAuthorityImpl(fc,
		log,
		stats,
		1, testKeyPolicy, 0, true, false, 300*24*time.Hour, 7*24*time.Hour, nil, noopCAA{}, 0)
	ra.SA = ssa
	ra.VA = va
	ra.CA = ca
	ra.PA = pa
	ra.DNSClient = &bdns.MockDNSClient{}

	AuthzInitial.RegistrationID = Registration.ID

	challenges, combinations, _ := pa.ChallengesFor(AuthzInitial.Identifier, Registration.ID, false)
	AuthzInitial.Challenges = challenges
	AuthzInitial.Combinations = combinations

	AuthzFinal = AuthzInitial
	AuthzFinal.Status = "valid"
	exp := time.Now().Add(365 * 24 * time.Hour)
	AuthzFinal.Expires = &exp
	AuthzFinal.Challenges[0].Status = "valid"

	return va, ssa, ra, fc, cleanUp
}

func assertAuthzEqual(t *testing.T, a1, a2 core.Authorization) {
	test.Assert(t, a1.ID == a2.ID, "ret != DB: ID")
	test.Assert(t, a1.Identifier == a2.Identifier, "ret != DB: Identifier")
	test.Assert(t, a1.Status == a2.Status, "ret != DB: Status")
	test.Assert(t, a1.RegistrationID == a2.RegistrationID, "ret != DB: RegID")
	if a1.Expires == nil && a2.Expires == nil {
		return
	} else if a1.Expires == nil || a2.Expires == nil {
		t.Errorf("one and only one of authorization's Expires was nil; ret %v, DB %v", a1, a2)
	} else {
		test.Assert(t, a1.Expires.Equal(*a2.Expires), "ret != DB: Expires")
	}

	// Not testing: Challenges
}

func TestValidateContacts(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	ansible := "ansible:earth.sol.milkyway.laniakea/letsencrypt"
	validEmail := "mailto:admin@email.com"
	otherValidEmail := "mailto:other-admin@email.com"
	malformedEmail := "mailto:admin.com"
	nonASCII := "mailto:señor@email.com"

	err := ra.validateContacts(context.Background(), &[]string{})
	test.AssertNotError(t, err, "No Contacts")

	err = ra.validateContacts(context.Background(), &[]string{validEmail, otherValidEmail})
	test.AssertError(t, err, "Too Many Contacts")

	err = ra.validateContacts(context.Background(), &[]string{validEmail})
	test.AssertNotError(t, err, "Valid Email")

	err = ra.validateContacts(context.Background(), &[]string{malformedEmail})
	test.AssertError(t, err, "Malformed Email")

	err = ra.validateContacts(context.Background(), &[]string{ansible})
	test.AssertError(t, err, "Unknown scheme")

	err = ra.validateContacts(context.Background(), &[]string{""})
	test.AssertError(t, err, "Empty URL")

	err = ra.validateContacts(context.Background(), &[]string{nonASCII})
	test.AssertError(t, err, "Non ASCII email")
}

func TestValidateEmail(t *testing.T) {
	testFailures := []struct {
		input    string
		expected string
	}{
		{"an email`", unparseableEmailError.Error()},
		{"a@always.invalid", emptyDNSResponseError.Error()},
		{"a@email.com, b@email.com", multipleAddressError.Error()},
		{"a@always.error", "DNS problem: networking error looking up A for always.error"},
	}
	testSuccesses := []string{
		"a@email.com",
		"b@email.only",
		// A timeout during email validation is treated as a success. We treat email
		// validation during registration as a best-effort. See
		// https://github.com/letsencrypt/boulder/issues/2260 for more
		"a@always.timeout",
	}

	for _, tc := range testFailures {
		err := validateEmail(context.Background(), tc.input, &bdns.MockDNSClient{})
		if !berrors.Is(err, berrors.InvalidEmail) {
			t.Errorf("validateEmail(%q): got error %#v, expected type berrors.InvalidEmail", tc.input, err)
		}

		if err.Error() != tc.expected {
			t.Errorf("validateEmail(%q): got %#v, expected %#v",
				tc.input, err.Error(), tc.expected)
		}
	}

	for _, addr := range testSuccesses {
		if err := validateEmail(context.Background(), addr, &bdns.MockDNSClient{}); err != nil {
			t.Errorf("validateEmail(%q): expected success, but it failed: %#v",
				addr, err)
		}
	}
}

func TestNewRegistration(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	mailto := "mailto:foo@letsencrypt.org"
	input := core.Registration{
		Contact:   &[]string{mailto},
		Key:       &AccountKeyB,
		InitialIP: net.ParseIP("7.6.6.5"),
	}

	result, err := ra.NewRegistration(ctx, input)
	if err != nil {
		t.Fatalf("could not create new registration: %s", err)
	}

	test.Assert(t, core.KeyDigestEquals(result.Key, AccountKeyB), "Key didn't match")
	test.Assert(t, len(*result.Contact) == 1, "Wrong number of contacts")
	test.Assert(t, mailto == (*result.Contact)[0], "Contact didn't match")
	test.Assert(t, result.Agreement == "", "Agreement didn't default empty")

	reg, err := sa.GetRegistration(ctx, result.ID)
	test.AssertNotError(t, err, "Failed to retrieve registration")
	test.Assert(t, core.KeyDigestEquals(reg.Key, AccountKeyB), "Retrieved registration differed.")
}

type mockSAFailsNewRegistration struct {
	mocks.StorageAuthority
}

func (ms *mockSAFailsNewRegistration) NewRegistration(ctx context.Context, reg core.Registration) (core.Registration, error) {
	return core.Registration{}, fmt.Errorf("too bad")
}

func TestNewRegistrationSAFailure(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.SA = &mockSAFailsNewRegistration{}
	input := core.Registration{
		Contact:   &[]string{"mailto:test@example.com"},
		Key:       &AccountKeyB,
		InitialIP: net.ParseIP("7.6.6.5"),
	}

	result, err := ra.NewRegistration(ctx, input)
	if err == nil {
		t.Fatalf("NewRegistration should have failed when SA.NewRegistration failed %#v", result.Key)
	}
}

func TestNewRegistrationNoFieldOverwrite(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	mailto := "mailto:foo@letsencrypt.org"
	input := core.Registration{
		ID:        23,
		Key:       &AccountKeyC,
		Contact:   &[]string{mailto},
		Agreement: "I agreed",
		InitialIP: net.ParseIP("5.0.5.0"),
	}

	result, err := ra.NewRegistration(ctx, input)
	test.AssertNotError(t, err, "Could not create new registration")

	test.Assert(t, result.ID != 23, "ID shouldn't be set by user")
	// TODO: Enable this test case once we validate terms agreement.
	//test.Assert(t, result.Agreement != "I agreed", "Agreement shouldn't be set with invalid URL")
}

func TestNewRegistrationBadKey(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	mailto := "mailto:foo@letsencrypt.org"
	input := core.Registration{
		Contact: &[]string{mailto},
		Key:     &ShortKey,
	}

	_, err := ra.NewRegistration(ctx, input)
	test.AssertError(t, err, "Should have rejected authorization with short key")
}

// testKey returns a random 2048 bit RSA public key for test registrations
func testKey() *rsa.PublicKey {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &key.PublicKey
}

func TestNewRegistrationRateLimit(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Specify a dummy rate limit policy that allows 1 registration per exact IP
	// match, and 2 per range.
	ra.rlPolicies = &dummyRateLimitConfig{
		RegistrationsPerIPPolicy: ratelimit.RateLimitPolicy{
			Threshold: 1,
			Window:    cmd.ConfigDuration{Duration: 24 * 90 * time.Hour},
		},
		RegistrationsPerIPRangePolicy: ratelimit.RateLimitPolicy{
			Threshold: 2,
			Window:    cmd.ConfigDuration{Duration: 24 * 90 * time.Hour},
		},
	}

	// Create one registration for an IPv4 address
	mailto := "mailto:foo@letsencrypt.org"
	reg := core.Registration{
		Contact:   &[]string{mailto},
		Key:       &jose.JSONWebKey{Key: testKey()},
		InitialIP: net.ParseIP("7.6.6.5"),
	}

	// There should be no errors - it is within the RegistrationsPerIP rate limit
	_, err := ra.NewRegistration(ctx, reg)
	test.AssertNotError(t, err, "Unexpected error adding new IPv4 registration")

	// Create another registration for the same IPv4 address by changing the key
	reg.Key = &jose.JSONWebKey{Key: testKey()}

	// There should be an error since a 2nd registration will exceed the
	// RegistrationsPerIP rate limit
	_, err = ra.NewRegistration(ctx, reg)
	test.AssertError(t, err, "No error adding duplicate IPv4 registration")
	test.AssertEquals(t, err.Error(), "too many registrations for this IP: see https://letsencrypt.org/docs/rate-limits/")

	// Create a registration for an IPv6 address
	reg.Key = &jose.JSONWebKey{Key: testKey()}
	reg.InitialIP = net.ParseIP("2001:cdba:1234:5678:9101:1121:3257:9652")

	// There should be no errors - it is within the RegistrationsPerIP rate limit
	_, err = ra.NewRegistration(ctx, reg)
	test.AssertNotError(t, err, "Unexpected error adding a new IPv6 registration")

	// Create a 2nd registration for the IPv6 address by changing the key
	reg.Key = &jose.JSONWebKey{Key: testKey()}

	// There should be an error since a 2nd reg for the same IPv6 address will
	// exceed the RegistrationsPerIP rate limit
	_, err = ra.NewRegistration(ctx, reg)
	test.AssertError(t, err, "No error adding duplicate IPv6 registration")
	test.AssertEquals(t, err.Error(), "too many registrations for this IP: see https://letsencrypt.org/docs/rate-limits/")

	// Create a registration for an IPv6 address in the same /48
	reg.Key = &jose.JSONWebKey{Key: testKey()}
	reg.InitialIP = net.ParseIP("2001:cdba:1234:5678:9101:1121:3257:9653")

	// There should be no errors since two IPv6 addresses in the same /48 is
	// within the RegistrationsPerIPRange limit
	_, err = ra.NewRegistration(ctx, reg)
	test.AssertNotError(t, err, "Unexpected error adding second IPv6 registration in the same /48")

	// Create a registration for yet another IPv6 address in the same /48
	reg.Key = &jose.JSONWebKey{Key: testKey()}
	reg.InitialIP = net.ParseIP("2001:cdba:1234:5678:9101:1121:3257:9654")

	// There should be an error since three registrations within the same IPv6
	// /48 is outside of the RegistrationsPerIPRange limit
	_, err = ra.NewRegistration(ctx, reg)
	test.AssertError(t, err, "No error adding a third IPv6 registration in the same /48")
	test.AssertEquals(t, err.Error(), "too many registrations for this IP range: see https://letsencrypt.org/docs/rate-limits/")
}

type NoUpdateSA struct {
	mocks.StorageAuthority
}

func (sa NoUpdateSA) UpdateRegistration(_ context.Context, _ core.Registration) error {
	return fmt.Errorf("UpdateRegistration() is mocked to always error")
}

func TestUpdateRegistrationSame(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	mailto := "mailto:foo@letsencrypt.org"

	// Make a new registration with AccountKeyC and a Contact
	input := core.Registration{
		Key:       &AccountKeyC,
		Contact:   &[]string{mailto},
		Agreement: "I agreed",
		InitialIP: net.ParseIP("5.0.5.0"),
	}
	createResult, err := ra.NewRegistration(ctx, input)
	test.AssertNotError(t, err, "Could not create new registration")
	id := createResult.ID

	// Switch to a mock SA that will always error if UpdateRegistration() is called
	ra.SA = &NoUpdateSA{}

	// Make an update to the registration with the same Contact & Agreement values.
	updateSame := core.Registration{
		ID:        id,
		Key:       &AccountKeyC,
		Contact:   &[]string{mailto},
		Agreement: "I agreed",
	}

	// The update operation should *not* error, even with the NoUpdateSA because
	// UpdateRegistration() should not be called when the update content doesn't
	// actually differ from the existing content
	_, err = ra.UpdateRegistration(ctx, input, updateSame)
	test.AssertNotError(t, err, "Error updating registration")
}

func TestNewAuthorization(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	_, err := ra.NewAuthorization(ctx, AuthzRequest, 0)
	test.AssertError(t, err, "Authorization cannot have registrationID == 0")

	authz, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization failed")

	// Verify that returned authz same as DB
	dbAuthz, err := sa.GetAuthorization(ctx, authz.ID)
	test.AssertNotError(t, err, "Could not fetch authorization from database")
	assertAuthzEqual(t, authz, dbAuthz)

	// Verify that the returned authz has the right information
	test.Assert(t, authz.RegistrationID == Registration.ID, "Initial authz did not get the right registration ID")
	test.Assert(t, authz.Identifier == AuthzRequest.Identifier, "Initial authz had wrong identifier")
	test.Assert(t, authz.Status == core.StatusPending, "Initial authz not pending")

	// TODO Verify that challenges are correct
	test.Assert(t, len(authz.Challenges) == len(SupportedChallenges), "Incorrect number of challenges returned")
	test.Assert(t, SupportedChallenges[authz.Challenges[0].Type], fmt.Sprintf("Unsupported challenge: %s", authz.Challenges[0].Type))
	test.Assert(t, SupportedChallenges[authz.Challenges[1].Type], fmt.Sprintf("Unsupported challenge: %s", authz.Challenges[1].Type))
	test.AssertNotError(t, authz.Challenges[0].CheckConsistencyForClientOffer(), "CheckConsistencyForClientOffer for Challenge 0 returned an error")
	test.AssertNotError(t, authz.Challenges[1].CheckConsistencyForClientOffer(), "CheckConsistencyForClientOffer for Challenge 1 returned an error")
}

func TestReuseValidAuthorization(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Turn on AuthZ Reuse
	ra.reuseValidAuthz = true

	// Create one finalized authorization
	finalAuthz := AuthzInitial
	finalAuthz.Status = "valid"
	exp := ra.clk.Now().Add(365 * 24 * time.Hour)
	finalAuthz.Expires = &exp
	finalAuthz.Challenges[0].Status = "valid"
	finalAuthz.Challenges[0].Type = core.ChallengeTypeHTTP01
	finalAuthz.RegistrationID = Registration.ID
	finalAuthz, err := sa.NewPendingAuthorization(ctx, finalAuthz)
	test.AssertNotError(t, err, "Could not store test pending authorization")
	err = sa.FinalizeAuthorization(ctx, finalAuthz)
	test.AssertNotError(t, err, "Could not finalize test pending authorization")

	// Now create another authorization for the same Reg.ID/domain
	secondAuthz, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization for secondAuthz failed")

	// The first authz should be reused as the second and thus have the same ID
	test.AssertEquals(t, finalAuthz.ID, secondAuthz.ID)

	// The second authz shouldn't be pending, it should be valid (that's why it
	// was reused)
	test.AssertEquals(t, secondAuthz.Status, core.StatusValid)

	// It should have one http challenge already marked valid
	httpIndex := ResponseIndex
	httpChallenge := secondAuthz.Challenges[httpIndex]
	test.AssertEquals(t, httpChallenge.Type, core.ChallengeTypeHTTP01)
	test.AssertEquals(t, httpChallenge.Status, core.StatusValid)

	// It should have one SNI challenge that is pending
	sniIndex := httpIndex + 1
	sniChallenge := secondAuthz.Challenges[sniIndex]
	test.AssertEquals(t, sniChallenge.Type, core.ChallengeTypeTLSSNI01)
	test.AssertEquals(t, sniChallenge.Status, core.StatusPending)

	// Sending an update to this authz for an already valid challenge should do
	// nothing (but produce no error), since it is already a valid authz
	response, err := makeResponse(httpChallenge)
	test.AssertNotError(t, err, "Unable to construct response to secondAuthz http challenge")
	secondAuthz, err = ra.UpdateAuthorization(ctx, secondAuthz, httpIndex, response)
	test.AssertNotError(t, err, "UpdateAuthorization on secondAuthz http failed")
	test.AssertEquals(t, finalAuthz.ID, secondAuthz.ID)
	test.AssertEquals(t, secondAuthz.Status, core.StatusValid)

	// Similarly, sending an update to this authz for a pending challenge should do
	// nothing (but produce no error), since the overall authz is already valid
	response, err = makeResponse(sniChallenge)
	test.AssertNotError(t, err, "Unable to construct response to secondAuthz sni challenge")
	secondAuthz, err = ra.UpdateAuthorization(ctx, secondAuthz, sniIndex, response)
	test.AssertNotError(t, err, "UpdateAuthorization on secondAuthz sni failed")
	test.AssertEquals(t, finalAuthz.ID, secondAuthz.ID)
	test.AssertEquals(t, secondAuthz.Status, core.StatusValid)

	// Test that a valid authorization that used a challenge which has been disabled
	// is not reused
	_ = features.Set(map[string]bool{"EnforceChallengeDisable": true})
	pa, err := policy.New(map[string]bool{
		core.ChallengeTypeHTTP01:   false,
		core.ChallengeTypeTLSSNI01: true,
		core.ChallengeTypeDNS01:    true,
	})
	test.AssertNotError(t, err, "Couldn't create PA")
	err = pa.SetHostnamePolicyFile("../test/hostname-policy.json")
	test.AssertNotError(t, err, "Couldn't set hostname policy")
	ra.PA = pa
	newAuthz, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization for secondAuthz failed")
	test.Assert(t, finalAuthz.ID != newAuthz.ID, "NewAuthorization reused a valid authz with a disabled challenge type")
}

func TestReusePendingAuthorization(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	_ = features.Set(map[string]bool{"ReusePendingAuthz": true})
	defer features.Reset()

	// Create one pending authorization
	firstAuthz, err := ra.NewAuthorization(ctx, AuthzInitial, Registration.ID)
	test.AssertNotError(t, err, "Could not store test pending authorization")

	// Create another one with the same identifier
	secondAuthz, err := ra.NewAuthorization(ctx, core.Authorization{
		Identifier: AuthzInitial.Identifier,
	}, Registration.ID)
	test.AssertNotError(t, err, "Could not store test pending authorization")

	// The first authz should be reused as the second and thus have the same ID
	test.AssertEquals(t, firstAuthz.ID, secondAuthz.ID)
	test.AssertEquals(t, secondAuthz.Status, core.StatusPending)

	otherReg, err := sa.NewRegistration(ctx, core.Registration{
		Key:       &AccountKeyB,
		InitialIP: net.ParseIP("3.2.3.3"),
		Status:    core.StatusValid,
	})
	test.AssertNotError(t, err, "Creating otherReg")
	// An authz created under another registration ID should not be reused.
	thirdAuthz, err := ra.NewAuthorization(ctx, core.Authorization{
		Identifier: AuthzInitial.Identifier,
	}, otherReg.ID)
	test.AssertNotError(t, err, "Could not store test pending authorization")
	if thirdAuthz.ID == firstAuthz.ID {
		t.Error("Authorization was reused for a different account.")
	}
}

type mockSAWithBadGetValidAuthz struct {
	mocks.StorageAuthority
}

func (m mockSAWithBadGetValidAuthz) GetValidAuthorizations(
	ctx context.Context,
	registrationID int64,
	names []string,
	now time.Time) (map[string]*core.Authorization, error) {
	return nil, fmt.Errorf("mockSAWithBadGetValidAuthz always errors!")
}

func TestReuseAuthorizationFaultySA(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Turn on AuthZ Reuse
	ra.reuseValidAuthz = true

	// Use a mock SA that always fails `GetValidAuthorizations`
	mockSA := &mockSAWithBadGetValidAuthz{}
	ra.SA = mockSA

	// We expect that calling NewAuthorization will fail gracefully with an error
	// about the existing validations
	_, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertEquals(t, err.Error(), "unable to get existing validations for regID: 1, identifier: not-example.com, mockSAWithBadGetValidAuthz always errors!")
}

func TestReuseAuthorizationDisabled(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Create one finalized authorization
	finalAuthz := AuthzInitial
	finalAuthz.Status = "valid"
	exp := ra.clk.Now().Add(365 * 24 * time.Hour)
	finalAuthz.Expires = &exp
	finalAuthz.Challenges[0].Status = "valid"
	finalAuthz.RegistrationID = Registration.ID
	finalAuthz, err := sa.NewPendingAuthorization(ctx, finalAuthz)
	test.AssertNotError(t, err, "Could not store test pending authorization")
	err = sa.FinalizeAuthorization(ctx, finalAuthz)
	test.AssertNotError(t, err, "Could not finalize test pending authorization")

	// Now create another authorization for the same Reg.ID/domain
	secondAuthz, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization for secondAuthz failed")

	// The second authz should not have the same ID as the previous AuthZ,
	// because we have set `reuseValidAuthZ` to false. It should be a fresh
	// & unique authz
	test.AssertNotEquals(t, finalAuthz.ID, secondAuthz.ID)

	// The second authz shouldn't be valid, but pending since it is a brand new
	// authz, not a reused one
	test.AssertEquals(t, secondAuthz.Status, core.StatusPending)
}

func TestReuseExpiringAuthorization(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Turn on AuthZ Reuse
	ra.reuseValidAuthz = true

	// Create one finalized authorization that expires in 12 hours from now
	expiringAuth := AuthzInitial
	expiringAuth.Status = "valid"
	exp := ra.clk.Now().Add(12 * time.Hour)
	expiringAuth.Expires = &exp
	expiringAuth.Challenges[0].Status = "valid"
	expiringAuth.RegistrationID = Registration.ID
	expiringAuth, err := sa.NewPendingAuthorization(ctx, expiringAuth)
	test.AssertNotError(t, err, "Could not store test pending authorization")
	err = sa.FinalizeAuthorization(ctx, expiringAuth)
	test.AssertNotError(t, err, "Could not finalize test pending authorization")

	// Now create another authorization for the same Reg.ID/domain
	secondAuthz, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization for secondAuthz failed")

	// The second authz should not have the same ID as the previous AuthZ,
	// because the existing valid authorization expires within 1 day from now
	test.AssertNotEquals(t, expiringAuth.ID, secondAuthz.ID)

	// The second authz shouldn't be valid, but pending since it is a brand new
	// authz, not a reused one
	test.AssertEquals(t, secondAuthz.Status, core.StatusPending)
}

func TestNewAuthorizationCapitalLetters(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	authzReq := core.Authorization{
		Identifier: core.AcmeIdentifier{
			Type:  core.IdentifierDNS,
			Value: "NOT-example.COM",
		},
	}
	authz, err := ra.NewAuthorization(ctx, authzReq, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization failed")
	test.AssertEquals(t, "not-example.com", authz.Identifier.Value)

	dbAuthz, err := sa.GetAuthorization(ctx, authz.ID)
	test.AssertNotError(t, err, "Could not fetch authorization from database")
	assertAuthzEqual(t, authz, dbAuthz)
}

func TestNewAuthorizationInvalidName(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	authzReq := core.Authorization{
		Identifier: core.AcmeIdentifier{
			Type:  core.IdentifierDNS,
			Value: "127.0.0.1",
		},
	}
	_, err := ra.NewAuthorization(ctx, authzReq, Registration.ID)
	if err == nil {
		t.Fatalf("NewAuthorization succeeded for 127.0.0.1, should have failed")
	}
	if !berrors.Is(err, berrors.Malformed) {
		t.Errorf("expected berrors.BoulderError with internal type berrors.Malformed, got %T", err)
	}
}

func TestUpdateAuthorization(t *testing.T) {
	va, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// We know this is OK because of TestNewAuthorization
	authz, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization failed")

	response, err := makeResponse(authz.Challenges[ResponseIndex])
	test.AssertNotError(t, err, "Unable to construct response to challenge")
	authz, err = ra.UpdateAuthorization(ctx, authz, ResponseIndex, response)
	test.AssertNotError(t, err, "UpdateAuthorization failed")
	var vaAuthz core.Authorization
	select {
	case a := <-va.argument:
		vaAuthz = a
	case <-time.After(time.Second):
		t.Fatal("Timed out waiting for DummyValidationAuthority.PerformValidation to complete")
	}

	// Verify that returned authz same as DB
	dbAuthz, err := sa.GetAuthorization(ctx, authz.ID)
	test.AssertNotError(t, err, "Could not fetch authorization from database")
	assertAuthzEqual(t, authz, dbAuthz)

	// Verify that the VA got the authz, and it's the same as the others
	assertAuthzEqual(t, authz, vaAuthz)

	// Verify that the responses are reflected
	test.Assert(t, len(vaAuthz.Challenges) > 0, "Authz passed to VA has no challenges")
}

func TestUpdateAuthorizationExpired(t *testing.T) {
	_, _, ra, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	authz, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization failed")

	expiry := fc.Now().Add(-2 * time.Hour)
	authz.Expires = &expiry

	response, err := makeResponse(authz.Challenges[ResponseIndex])

	authz, err = ra.UpdateAuthorization(ctx, authz, ResponseIndex, response)
	test.AssertError(t, err, "Updated expired authorization")
}

func TestUpdateAuthorizationAlreadyValid(t *testing.T) {
	va, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Create a finalized authorization
	finalAuthz := AuthzInitial
	finalAuthz.Status = "valid"
	exp := ra.clk.Now().Add(365 * 24 * time.Hour)
	finalAuthz.Expires = &exp
	finalAuthz.Challenges[0].Status = "valid"
	finalAuthz.RegistrationID = Registration.ID
	finalAuthz, err := sa.NewPendingAuthorization(ctx, finalAuthz)
	test.AssertNotError(t, err, "Could not create pending authorization")
	err = sa.FinalizeAuthorization(ctx, finalAuthz)
	test.AssertNotError(t, err, "Could not finalize pending authorization")

	response, err := makeResponse(finalAuthz.Challenges[ResponseIndex])
	test.AssertNotError(t, err, "Unable to construct response to challenge")
	finalAuthz.Challenges[ResponseIndex].Type = core.ChallengeTypeHTTP01
	finalAuthz.Challenges[ResponseIndex].Status = core.StatusPending
	va.RecordsReturn = []core.ValidationRecord{
		{Hostname: "example.com"}}
	va.ProblemReturn = nil

	// A subsequent call to update the authorization should return the expected error
	_, err = ra.UpdateAuthorization(ctx, finalAuthz, ResponseIndex, response)
	test.Assert(t, berrors.Is(err, berrors.WrongAuthorizationState),
		"FinalizeAuthorization of valid authz didn't return a berrors.WrongAuthorizationState")
}

func TestUpdateAuthorizationNewRPC(t *testing.T) {
	va, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// We know this is OK because of TestNewAuthorization
	authz, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization failed")

	response, err := makeResponse(authz.Challenges[ResponseIndex])
	test.AssertNotError(t, err, "Unable to construct response to challenge")
	authz.Challenges[ResponseIndex].Type = core.ChallengeTypeDNS01
	va.RecordsReturn = []core.ValidationRecord{
		{Hostname: "example.com"}}
	va.ProblemReturn = nil

	authz, err = ra.UpdateAuthorization(ctx, authz, ResponseIndex, response)
	test.AssertNotError(t, err, "UpdateAuthorization failed")
	var vaAuthz core.Authorization
	select {
	case a := <-va.argument:
		vaAuthz = a
	case <-time.After(time.Second):
		t.Fatal("Timed out waiting for DummyValidationAuthority.PerformValidation to complete")
	}

	// Verify that returned authz same as DB
	dbAuthz, err := sa.GetAuthorization(ctx, authz.ID)
	test.AssertNotError(t, err, "Could not fetch authorization from database")
	assertAuthzEqual(t, authz, dbAuthz)

	// Verify that the VA got the authz, and it's the same as the others
	assertAuthzEqual(t, authz, vaAuthz)

	// Verify that the responses are reflected
	test.Assert(t, len(vaAuthz.Challenges) > 0, "Authz passed to VA has no challenges")
	test.Assert(t, authz.Challenges[ResponseIndex].Status == core.StatusValid, "challenge was not marked as valid")
}

func TestCertificateKeyNotEqualAccountKey(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	authz := core.Authorization{RegistrationID: 1}
	authz, err := sa.NewPendingAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Could not store test data")
	authz.Identifier = core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: "www.example.com",
	}
	csr := x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKey:          AccountKeyA.Key,
		DNSNames:           []string{"www.example.com"},
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csr, AccountPrivateKey.Key)
	test.AssertNotError(t, err, "Failed to sign CSR")
	parsedCSR, err := x509.ParseCertificateRequest(csrBytes)
	test.AssertNotError(t, err, "Failed to parse CSR")
	err = sa.FinalizeAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Could not store test data")
	certRequest := core.CertificateRequest{
		CSR: parsedCSR,
	}

	// Registration has key == AccountKeyA
	_, err = ra.NewCertificate(ctx, certRequest, Registration.ID)
	test.AssertError(t, err, "Should have rejected cert with key = account key")
	test.AssertEquals(t, err.Error(), "certificate public key must be different than account key")
}

func TestAuthorizationRequired(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	AuthzFinal.RegistrationID = 1
	AuthzFinal, err := sa.NewPendingAuthorization(ctx, AuthzFinal)
	test.AssertNotError(t, err, "Could not store test data")
	err = sa.FinalizeAuthorization(ctx, AuthzFinal)
	test.AssertNotError(t, err, "Could not store test data")

	// ExampleCSR requests not-example.com and www.not-example.com,
	// but the authorization only covers not-example.com
	certRequest := core.CertificateRequest{
		CSR: ExampleCSR,
	}

	_, err = ra.NewCertificate(ctx, certRequest, 1)
	test.Assert(t, err != nil, "Issued certificate with insufficient authorization")
}

func TestNewCertificate(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	AuthzFinal.RegistrationID = Registration.ID
	AuthzFinal, err := sa.NewPendingAuthorization(ctx, AuthzFinal)
	test.AssertNotError(t, err, "Could not store test data")
	err = sa.FinalizeAuthorization(ctx, AuthzFinal)
	test.AssertNotError(t, err, "Could not store test data")

	// Inject another final authorization to cover www.not-example.com
	authzFinalWWW := AuthzFinal
	authzFinalWWW.Identifier.Value = "www.not-example.com"
	authzFinalWWW, err = sa.NewPendingAuthorization(ctx, authzFinalWWW)
	test.AssertNotError(t, err, "Could not store test data")
	err = sa.FinalizeAuthorization(ctx, authzFinalWWW)
	test.AssertNotError(t, err, "Could not store test data")

	// Check that we fail if the CSR signature is invalid
	ExampleCSR.Signature[0]++
	certRequest := core.CertificateRequest{
		CSR: ExampleCSR,
	}

	_, err = ra.NewCertificate(ctx, certRequest, Registration.ID)
	ExampleCSR.Signature[0]--
	test.AssertError(t, err, "Failed to check CSR signature")

	// Before issuance the issuanceExpvar should be 0
	test.AssertEquals(t, issuanceExpvar.String(), "0")

	// Check that we don't fail on case mismatches
	ExampleCSR.Subject.CommonName = "www.NOT-example.com"
	certRequest = core.CertificateRequest{
		CSR: ExampleCSR,
	}

	if err := ra.updateIssuedCount(); err != nil {
		t.Fatal("Updating issuance count:", err)
	}

	cert, err := ra.NewCertificate(ctx, certRequest, Registration.ID)
	test.AssertNotError(t, err, "Failed to issue certificate")

	// After issuance the issuanceExpvar should be the current timestamp
	now := ra.clk.Now()
	test.AssertEquals(t, issuanceExpvar.String(), fmt.Sprintf("%d", now.Unix()))

	_, err = x509.ParseCertificate(cert.DER)
	test.AssertNotError(t, err, "Failed to parse certificate")
}

func TestTotalCertRateLimit(t *testing.T) {
	_, sa, ra, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	ra.rlPolicies = &dummyRateLimitConfig{
		TotalCertificatesPolicy: ratelimit.RateLimitPolicy{
			Threshold: 1,
			Window:    cmd.ConfigDuration{Duration: 24 * 90 * time.Hour},
		},
	}
	fc.Add(24 * 90 * time.Hour)

	AuthzFinal.RegistrationID = Registration.ID
	AuthzFinal, err := sa.NewPendingAuthorization(ctx, AuthzFinal)
	test.AssertNotError(t, err, "Could not store test data")
	err = sa.FinalizeAuthorization(ctx, AuthzFinal)

	// Inject another final authorization to cover www.not-example.com
	authzFinalWWW := AuthzFinal
	authzFinalWWW.Identifier.Value = "www.not-example.com"
	authzFinalWWW, err = sa.NewPendingAuthorization(ctx, authzFinalWWW)
	test.AssertNotError(t, err, "Could not store test data")
	err = sa.FinalizeAuthorization(ctx, authzFinalWWW)
	test.AssertNotError(t, err, "Could not store test data")

	ExampleCSR.Subject.CommonName = "www.NOT-example.com"
	certRequest := core.CertificateRequest{
		CSR: ExampleCSR,
	}

	_, err = ra.NewCertificate(ctx, certRequest, Registration.ID)
	test.AssertError(t, err, "Expected to fail issuance when updateIssuedCount not yet called")

	if err := ra.updateIssuedCount(); err != nil {
		t.Fatal("Updating issuance count:", err)
	}

	// TODO(jsha): Since we're using a real SA rather than a mock, we call
	// NewCertificate twice and insert the first result into the SA. Instead we
	// should mock out the SA and have it return the cert count that we want.
	cert, err := ra.NewCertificate(ctx, certRequest, Registration.ID)
	test.AssertNotError(t, err, "Failed to issue certificate")
	_, err = sa.AddCertificate(ctx, cert.DER, Registration.ID, nil)
	test.AssertNotError(t, err, "Failed to store certificate")

	fc.Add(time.Hour)
	if err := ra.updateIssuedCount(); err != nil {
		t.Fatal("Updating issuance count:", err)
	}

	_, err = ra.NewCertificate(ctx, certRequest, Registration.ID)
	test.AssertError(t, err, "Total certificate rate limit failed")

	fc.Add(time.Hour)
	_, err = ra.NewCertificate(ctx, certRequest, Registration.ID)
	test.AssertError(t, err, "Expected to fail issuance when updateIssuedCount too long out of date")
}

func TestAuthzRateLimiting(t *testing.T) {
	_, _, ra, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	ra.rlPolicies = &dummyRateLimitConfig{
		PendingAuthorizationsPerAccountPolicy: ratelimit.RateLimitPolicy{
			Threshold: 1,
			Window:    cmd.ConfigDuration{Duration: 24 * 90 * time.Hour},
		},
	}
	fc.Add(24 * 90 * time.Hour)

	// Should be able to create an authzRequest
	authz, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization failed")

	fc.Add(time.Hour)

	// Second one should trigger rate limit
	_, err = ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertError(t, err, "Pending Authorization rate limit failed.")

	// Finalize pending authz
	err = ra.onValidationUpdate(ctx, authz)
	test.AssertNotError(t, err, "Could not store test data")

	// Try to create a new authzRequest, should be fine now.
	_, err = ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization failed")
}

func TestNewOrderRateLimiting(t *testing.T) {
	// Only run under test/config-next config where 20170731115209_AddOrders.sql
	// has been applied
	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		return
	}

	_, _, ra, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	_ = features.Set(map[string]bool{"EnforceChallengeDisable": true})

	// Create a dummy rate limit config that sets a PendingOrdersPerAccount rate
	// limit with a very low threshold
	ra.rlPolicies = &dummyRateLimitConfig{
		PendingOrdersPerAccountPolicy: ratelimit.RateLimitPolicy{
			Threshold: 1,
			Window:    cmd.ConfigDuration{Duration: 7 * 24 * time.Hour},
		},
	}
	// Set the RA up to consider an order valid for one hour
	ra.orderLifetime = time.Hour

	// To start, it should be possible to create a new order
	_, err := ra.NewOrder(ctx, &rapb.NewOrderRequest{
		RegistrationID: &Registration.ID,
		Names:          []string{"example.com"},
	})
	test.AssertNotError(t, err, "NewOrder failed")

	// A subsequent new order request should fail
	_, err = ra.NewOrder(ctx, &rapb.NewOrderRequest{
		RegistrationID: &Registration.ID,
		Names:          []string{"zombo.com"},
	})
	test.AssertError(t, err, "NewOrder did not get rate limited")

	// Advancing the clock by hour should expire the first pending order and allow creation of another
	fc.Add(time.Hour)

	// Create one finalized Authz for Registration.ID for "not-example.com" and
	// "www.not-example.com" to allow the order we will create next to be
	// finalized
	exp := ra.clk.Now().Add(time.Hour)
	finalAuthz := AuthzInitial
	finalAuthz.Identifier = core.AcmeIdentifier{Type: "dns", Value: "not-example.com"}
	finalAuthz.Status = "valid"
	finalAuthz.Expires = &exp
	finalAuthz.Challenges[0].Status = "valid"
	finalAuthz.RegistrationID = Registration.ID
	finalAuthz, err = ra.SA.NewPendingAuthorization(ctx, finalAuthz)
	test.AssertNotError(t, err, "Could not store test pending authorization")
	err = ra.SA.FinalizeAuthorization(ctx, finalAuthz)
	test.AssertNotError(t, err, "Could not finalize test pending authorization")

	finalAuthzB := AuthzInitial
	finalAuthzB.Identifier = core.AcmeIdentifier{Type: "dns", Value: "www.not-example.com"}
	finalAuthzB.Status = "valid"
	finalAuthzB.Expires = &exp
	finalAuthzB.Challenges[0].Status = "valid"
	finalAuthzB.RegistrationID = Registration.ID
	finalAuthzB, err = ra.SA.NewPendingAuthorization(ctx, finalAuthzB)
	test.AssertNotError(t, err, "Could not store 2nd test pending authorization")
	err = ra.SA.FinalizeAuthorization(ctx, finalAuthzB)
	test.AssertNotError(t, err, "Could not finalize 2nd test pending authorization")

	order, err := ra.NewOrder(ctx, &rapb.NewOrderRequest{
		RegistrationID: &Registration.ID,
		Names:          []string{"not-example.com", "www.not-example.com"},
	})
	test.AssertNotError(t, err, "NewOrder failed")

	// Swallowing errors here because the CSRPEM is hardcoded test data expected
	// to parse in all instance
	validCSRBlock, _ := pem.Decode(CSRPEM)
	validCSR, _ := x509.ParseCertificateRequest(validCSRBlock.Bytes)

	// Finalize the order with a CSR to change it from pending status to valid status
	_, err = ra.FinalizeOrder(ctx, &rapb.FinalizeOrderRequest{
		Order: order,
		Csr:   validCSR.Raw,
	})
	test.AssertNotError(t, err, "Unable to finalize test order")

	// A subsequent new order request should succeed because the previous order is
	// no longer pending
	_, err = ra.NewOrder(ctx, &rapb.NewOrderRequest{
		RegistrationID: &Registration.ID,
		Names:          []string{"zombo.gov"},
	})
	test.AssertNotError(t, err, "NewOrder failed")
}

func TestAuthzFailedRateLimiting(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	ra.rlPolicies = &dummyRateLimitConfig{
		InvalidAuthorizationsPerAccountPolicy: ratelimit.RateLimitPolicy{
			Threshold: 1,
			Window:    cmd.ConfigDuration{Duration: 1 * time.Hour},
		},
	}

	// override with our mockInvalidAuthorizationsAuthority for this specific test
	ra.SA = sagrpc.NewStorageAuthorityClient(&mockInvalidAuthorizationsAuthority{})
	// Should trigger rate limit
	_, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertError(t, err, "NewAuthorization did not encounter expected rate limit error")
	test.AssertEquals(t, err.Error(), "too many failed authorizations recently: see https://letsencrypt.org/docs/rate-limits/")
}

func TestDomainsForRateLimiting(t *testing.T) {
	domains, err := domainsForRateLimiting([]string{})
	test.AssertNotError(t, err, "failed on empty")
	test.AssertEquals(t, len(domains), 0)

	domains, err = domainsForRateLimiting([]string{"www.example.com", "example.com"})
	test.AssertNotError(t, err, "failed on example.com")
	test.AssertEquals(t, len(domains), 1)
	test.AssertEquals(t, domains[0], "example.com")

	domains, err = domainsForRateLimiting([]string{"www.example.com", "example.com", "www.example.co.uk"})
	test.AssertNotError(t, err, "failed on example.co.uk")
	test.AssertEquals(t, len(domains), 2)
	test.AssertEquals(t, domains[0], "example.co.uk")
	test.AssertEquals(t, domains[1], "example.com")

	domains, err = domainsForRateLimiting([]string{"www.example.com", "example.com", "www.example.co.uk", "co.uk"})
	test.AssertNotError(t, err, "should not fail on public suffix")
	test.AssertEquals(t, len(domains), 2)
	test.AssertEquals(t, domains[0], "example.co.uk")
	test.AssertEquals(t, domains[1], "example.com")

	domains, err = domainsForRateLimiting([]string{"foo.bar.baz.www.example.com", "baz.example.com"})
	test.AssertNotError(t, err, "failed on foo.bar.baz")
	test.AssertEquals(t, len(domains), 1)
	test.AssertEquals(t, domains[0], "example.com")

	domains, err = domainsForRateLimiting([]string{"github.io", "foo.github.io", "bar.github.io"})
	test.AssertNotError(t, err, "failed on public suffix private domain")
	test.AssertEquals(t, len(domains), 2)
	test.AssertEquals(t, domains[0], "bar.github.io")
	test.AssertEquals(t, domains[1], "foo.github.io")
}

func TestSuffixesForRateLimiting(t *testing.T) {
	suffixes, err := suffixesForRateLimiting([]string{})
	test.AssertNotError(t, err, "suffixiesForRateLimiting should not error with empty domains arg")
	test.AssertEquals(t, len(suffixes), 0)

	suffixes, err = suffixesForRateLimiting([]string{"www.example.com", "example.com"})
	test.AssertNotError(t, err, "should not fail on no public suffixes")
	test.AssertEquals(t, len(suffixes), 0)

	suffixes, err = suffixesForRateLimiting([]string{"www.example.com", "example.com", "www.example.co.uk", "co.uk"})
	test.AssertNotError(t, err, "should not fail on public suffix")
	test.AssertEquals(t, len(suffixes), 1)
	test.AssertEquals(t, suffixes[0], "co.uk")

	suffixes, err = suffixesForRateLimiting([]string{"github.io", "foo.github.io", "bar.github.io"})
	test.AssertNotError(t, err, "failed on public suffix private domain")
	test.AssertEquals(t, len(suffixes), 1)
	test.AssertEquals(t, suffixes[0], "github.io")

	suffixes, err = suffixesForRateLimiting([]string{"github.io", "foo.github.io", "www.example.com", "www.example.co.uk", "co.uk"})
	test.AssertNotError(t, err, "failed on mix of public suffix private domain and public suffix")
	test.AssertEquals(t, len(suffixes), 2)
	test.AssertEquals(t, suffixes[0], "co.uk")
	test.AssertEquals(t, suffixes[1], "github.io")
}

func TestRateLimitLiveReload(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// We'll work with a temporary file as the reloader monitored rate limit
	// policy file
	policyFile, tempErr := ioutil.TempFile("", "rate-limit-policies.yml")
	test.AssertNotError(t, tempErr, "should not fail to create TempFile")
	filename := policyFile.Name()
	defer os.Remove(filename)

	// Start with bodyOne in the temp file
	bodyOne, readErr := ioutil.ReadFile("../test/rate-limit-policies.yml")
	test.AssertNotError(t, readErr, "should not fail to read ../test/rate-limit-policies.yml")
	writeErr := ioutil.WriteFile(filename, bodyOne, 0644)
	test.AssertNotError(t, writeErr, "should not fail to write temp file")

	// Configure the RA to use the monitored temp file as the policy file
	err := ra.SetRateLimitPoliciesFile(filename)
	test.AssertNotError(t, err, "failed to SetRateLimitPoliciesFile")

	// Test some fields of the initial policy to ensure it loaded correctly
	test.AssertEquals(t, ra.rlPolicies.TotalCertificates().Threshold, 100000)
	test.AssertEquals(t, ra.rlPolicies.CertificatesPerName().Overrides["le.wtf"], 10000)
	test.AssertEquals(t, ra.rlPolicies.RegistrationsPerIP().Overrides["127.0.0.1"], 1000000)
	test.AssertEquals(t, ra.rlPolicies.PendingAuthorizationsPerAccount().Threshold, 3)
	test.AssertEquals(t, ra.rlPolicies.CertificatesPerFQDNSet().Overrides["le.wtf"], 10000)
	test.AssertEquals(t, ra.rlPolicies.CertificatesPerFQDNSet().Threshold, 5)

	// Write a different  policy YAML to the monitored file, expect a reload.
	// Sleep a few milliseconds before writing so the timestamp isn't identical to
	// when we wrote bodyOne to the file earlier.
	bodyTwo, readErr := ioutil.ReadFile("../test/rate-limit-policies-b.yml")
	test.AssertNotError(t, readErr, "should not fail to read ../test/rate-limit-policies-b.yml")
	time.Sleep(1 * time.Second)
	writeErr = ioutil.WriteFile(filename, bodyTwo, 0644)
	test.AssertNotError(t, writeErr, "should not fail to write temp file")

	// Sleep to allow the reloader a chance to catch that an update occurred
	time.Sleep(2 * time.Second)

	// Test fields of the policy to make sure writing the new policy to the monitored file
	// resulted in the runtime values being updated
	test.AssertEquals(t, ra.rlPolicies.TotalCertificates().Threshold, 99999)
	test.AssertEquals(t, ra.rlPolicies.CertificatesPerName().Overrides["le.wtf"], 9999)
	test.AssertEquals(t, ra.rlPolicies.CertificatesPerName().Overrides["le4.wtf"], 9999)
	test.AssertEquals(t, ra.rlPolicies.RegistrationsPerIP().Overrides["127.0.0.1"], 999990)
	test.AssertEquals(t, ra.rlPolicies.PendingAuthorizationsPerAccount().Threshold, 999)
	test.AssertEquals(t, ra.rlPolicies.CertificatesPerFQDNSet().Overrides["le.wtf"], 9999)
	test.AssertEquals(t, ra.rlPolicies.CertificatesPerFQDNSet().Threshold, 99999)
}

type mockSAWithNameCounts struct {
	mocks.StorageAuthority
	nameCounts  map[string]*sapb.CountByNames_MapElement
	exactCounts map[string]*sapb.CountByNames_MapElement
	t           *testing.T
	clk         clock.FakeClock
}

func (m mockSAWithNameCounts) CountCertificatesByNames(ctx context.Context, names []string, earliest, latest time.Time) (ret []*sapb.CountByNames_MapElement, err error) {
	if latest != m.clk.Now() {
		m.t.Error(fmt.Sprintf("incorrect latest: was %s, expected %s", latest, m.clk.Now()))
	}
	expectedEarliest := m.clk.Now().Add(-23 * time.Hour)
	if earliest != expectedEarliest {
		m.t.Errorf(fmt.Sprintf("incorrect earliest: was %s, expected %s", earliest, expectedEarliest))
	}
	var results []*sapb.CountByNames_MapElement
	for _, name := range names {
		if entry, ok := m.nameCounts[name]; ok {
			results = append(results, entry)
		}
	}
	return results, nil
}

func (m mockSAWithNameCounts) CountCertificatesByExactNames(ctx context.Context, names []string, earliest, latest time.Time) (ret []*sapb.CountByNames_MapElement, err error) {
	if latest != m.clk.Now() {
		m.t.Error(fmt.Sprintf("incorrect latest: was %s, expected %s", latest, m.clk.Now()))
	}
	expectedEarliest := m.clk.Now().Add(-23 * time.Hour)
	if earliest != expectedEarliest {
		m.t.Errorf(fmt.Sprintf("incorrect earliest: was %s, expected %s", earliest, expectedEarliest))
	}
	var results []*sapb.CountByNames_MapElement
	for _, name := range names {
		if entry, ok := m.exactCounts[name]; ok {
			results = append(results, entry)
		}
	}
	return results, nil
}

func nameCount(domain string, count int) *sapb.CountByNames_MapElement {
	pbInt := int64(count)
	return &sapb.CountByNames_MapElement{
		Name:  &domain,
		Count: &pbInt,
	}
}

func TestCheckCertificatesPerNameLimit(t *testing.T) {
	_, _, ra, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	rlp := ratelimit.RateLimitPolicy{
		Threshold: 3,
		Window:    cmd.ConfigDuration{Duration: 23 * time.Hour},
		Overrides: map[string]int{
			"bigissuer.com":     100,
			"smallissuer.co.uk": 1,
		},
	}

	mockSA := &mockSAWithNameCounts{
		nameCounts: map[string]*sapb.CountByNames_MapElement{
			"example.com": nameCount("example.com", 1),
		},
		clk: fc,
		t:   t,
	}

	ra.SA = mockSA

	// One base domain, below threshold
	err := ra.checkCertificatesPerNameLimit(ctx, []string{"www.example.com", "example.com"}, rlp, 99)
	test.AssertNotError(t, err, "rate limited example.com incorrectly")

	// One base domain, above threshold
	mockSA.nameCounts["example.com"] = nameCount("example.com", 10)
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"www.example.com", "example.com"}, rlp, 99)
	test.AssertError(t, err, "incorrectly failed to rate limit example.com")
	if !berrors.Is(err, berrors.RateLimit) {
		t.Errorf("Incorrect error type %#v", err)
	}

	// SA misbehaved and didn't send back a count for every input name
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"zombo.com", "www.example.com", "example.com"}, rlp, 99)
	test.AssertError(t, err, "incorrectly failed to error on misbehaving SA")

	// Two base domains, one above threshold but with an override.
	mockSA.nameCounts["example.com"] = nameCount("example.com", 0)
	mockSA.nameCounts["bigissuer.com"] = nameCount("bigissuer.com", 50)
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"www.example.com", "subdomain.bigissuer.com"}, rlp, 99)
	test.AssertNotError(t, err, "incorrectly rate limited bigissuer")

	// Two base domains, one above its override
	mockSA.nameCounts["example.com"] = nameCount("example.com", 0)
	mockSA.nameCounts["bigissuer.com"] = nameCount("bigissuer.com", 100)
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"www.example.com", "subdomain.bigissuer.com"}, rlp, 99)
	test.AssertError(t, err, "incorrectly failed to rate limit bigissuer")
	if !berrors.Is(err, berrors.RateLimit) {
		t.Errorf("Incorrect error type")
	}

	// One base domain, above its override (which is below threshold)
	mockSA.nameCounts["smallissuer.co.uk"] = nameCount("smallissuer.co.uk", 1)
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"www.smallissuer.co.uk"}, rlp, 99)
	test.AssertError(t, err, "incorrectly failed to rate limit smallissuer")
	if !berrors.Is(err, berrors.RateLimit) {
		t.Errorf("Incorrect error type %#v", err)
	}
}

// TestCheckExactCertificateLimit tests that the duplicate certificate limit
// applied to FQDN sets is respected.
func TestCheckExactCertificateLimit(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Create a rate limit with a small threshold
	const dupeCertLimit = 3
	rlp := ratelimit.RateLimitPolicy{
		Threshold: dupeCertLimit,
		Window:    cmd.ConfigDuration{Duration: 23 * time.Hour},
	}

	// Create a mock SA that has a count of already issued certificates for some
	// test names
	mockSA := &mockSAWithFQDNSet{
		nameCounts: map[string]*sapb.CountByNames_MapElement{
			"under.example.com": nameCount("under.example.com", dupeCertLimit-1),
			"equal.example.com": nameCount("equal.example.com", dupeCertLimit),
			"over.example.com":  nameCount("over.example.com", dupeCertLimit+1),
		},
		t: t,
	}
	ra.SA = mockSA

	testCases := []struct {
		Name        string
		Domain      string
		ExpectedErr error
	}{
		{
			Name:        "FQDN set issuances less than limit",
			Domain:      "under.example.com",
			ExpectedErr: nil,
		},
		{
			Name:        "FQDN set issuances equal to limit",
			Domain:      "equal.example.com",
			ExpectedErr: fmt.Errorf("too many certificates already issued for exact set of domains: equal.example.com: see https://letsencrypt.org/docs/rate-limits/"),
		},
		{
			Name:        "FQDN set issuances above limit",
			Domain:      "over.example.com",
			ExpectedErr: fmt.Errorf("too many certificates already issued for exact set of domains: over.example.com: see https://letsencrypt.org/docs/rate-limits/"),
		},
	}

	// For each test case we check that the certificatesPerFQDNSetLimit is applied
	// as we expect
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result := ra.checkCertificatesPerFQDNSetLimit(ctx, []string{tc.Domain}, rlp, 0)
			if tc.ExpectedErr == nil {
				test.AssertNotError(t, result, fmt.Sprintf("Expected no error for %q", tc.Domain))
			} else {
				test.AssertError(t, result, fmt.Sprintf("Expected error for %q", tc.Domain))
				test.AssertEquals(t, result.Error(), tc.ExpectedErr.Error())
			}
		})
	}
}

func TestRegistrationUpdate(t *testing.T) {
	oldURL := "http://old.invalid"
	newURL := "http://new.invalid"
	reg := core.Registration{
		ID:        1,
		Contact:   &[]string{oldURL},
		Agreement: "",
	}
	update := core.Registration{
		Contact:   &[]string{newURL},
		Agreement: "totally!",
	}

	changed := mergeUpdate(&reg, update)
	test.AssertEquals(t, changed, true)
	test.Assert(t, len(*reg.Contact) == 1 && (*reg.Contact)[0] == (*update.Contact)[0], "Contact was not updated %v != %v")
	test.Assert(t, reg.Agreement == update.Agreement, "Agreement was not updated")

	// Make sure that a `MergeUpdate` call with an empty string doesn't produce an
	// error and results in a change to the base reg.
	emptyUpdate := core.Registration{
		Contact:   &[]string{""},
		Agreement: "totally!",
	}
	changed = mergeUpdate(&reg, emptyUpdate)
	test.AssertEquals(t, changed, true)
}

func TestRegistrationContactUpdate(t *testing.T) {
	contactURL := "mailto://example@example.com"
	fullReg := core.Registration{
		ID:        1,
		Contact:   &[]string{contactURL},
		Agreement: "totally!",
	}

	// Test that a registration contact can be removed by updating with an empty
	// Contact slice.
	reg := fullReg
	var contactRemoveUpdate core.Registration
	contactRemoveJSON := []byte(`
	{
		"key": {
			"e": "AQAB",
			"kty": "RSA",
			"n": "tSwgy3ORGvc7YJI9B2qqkelZRUC6F1S5NwXFvM4w5-M0TsxbFsH5UH6adigV0jzsDJ5imAechcSoOhAh9POceCbPN1sTNwLpNbOLiQQ7RD5mY_"
		},
		"id": 1,
		"contact": [],
		"agreement": "totally!"
	}
	`)
	err := json.Unmarshal(contactRemoveJSON, &contactRemoveUpdate)
	test.AssertNotError(t, err, "Failed to unmarshal contactRemoveJSON")
	changed := mergeUpdate(&reg, contactRemoveUpdate)
	test.AssertEquals(t, changed, true)
	test.Assert(t, len(*reg.Contact) == 0, "Contact was not deleted in update")

	// Test that a registration contact isn't changed when an update is performed
	// with no Contact field
	reg = fullReg
	var contactSameUpdate core.Registration
	contactSameJSON := []byte(`
	{
		"key": {
			"e": "AQAB",
			"kty": "RSA",
			"n": "tSwgy3ORGvc7YJI9B2qqkelZRUC6F1S5NwXFvM4w5-M0TsxbFsH5UH6adigV0jzsDJ5imAechcSoOhAh9POceCbPN1sTNwLpNbOLiQQ7RD5mY_"
		},
		"id": 1,
		"agreement": "totally!"
	}
	`)
	err = json.Unmarshal(contactSameJSON, &contactSameUpdate)
	test.AssertNotError(t, err, "Failed to unmarshal contactSameJSON")
	changed = mergeUpdate(&reg, contactSameUpdate)
	test.AssertEquals(t, changed, false)
	test.Assert(t, len(*reg.Contact) == 1, "len(Contact) was updated unexpectedly")
	test.Assert(t, (*reg.Contact)[0] == "mailto://example@example.com", "Contact was changed unexpectedly")
}

func TestRegistrationKeyUpdate(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 512)
	test.AssertNotError(t, err, "rsa.GenerateKey() for oldKey failed")

	rA, rB := core.Registration{Key: &jose.JSONWebKey{Key: oldKey}}, core.Registration{}

	changed := mergeUpdate(&rA, rB)
	if changed {
		t.Fatal("mergeUpdate changed the key with empty update")
	}

	newKey, err := rsa.GenerateKey(rand.Reader, 1024)
	test.AssertNotError(t, err, "rsa.GenerateKey() for newKey failed")
	rB.Key = &jose.JSONWebKey{Key: newKey.Public()}

	changed = mergeUpdate(&rA, rB)
	if !changed {
		t.Fatal("mergeUpdate didn't change the key with non-empty update")
	}
	keysMatch, _ := core.PublicKeysEqual(rA.Key.Key, rB.Key.Key)
	if !keysMatch {
		t.Fatal("mergeUpdate didn't change the key despite setting returned bool")
	}
}

// A mockSAWithFQDNSet is a mock StorageAuthority that supports
// CountCertificatesByName as well as FQDNSetExists. This allows testing
// checkCertificatesPerNameRateLimit's FQDN exemption logic.
type mockSAWithFQDNSet struct {
	mocks.StorageAuthority
	fqdnSet    map[string]bool
	nameCounts map[string]*sapb.CountByNames_MapElement
	t          *testing.T
}

// Construct the FQDN Set key the same way as the SA - by using
// `core.UniqueLowerNames`, joining the names with a `,` and hashing them.
func (m mockSAWithFQDNSet) hashNames(names []string) string {
	names = core.UniqueLowerNames(names)
	hash := sha256.Sum256([]byte(strings.Join(names, ",")))
	return string(hash[:])
}

// Add a set of domain names to the FQDN set
func (m mockSAWithFQDNSet) addFQDNSet(names []string) {
	hash := m.hashNames(names)
	m.fqdnSet[hash] = true
}

// Search for a set of domain names in the FQDN set map
func (m mockSAWithFQDNSet) FQDNSetExists(_ context.Context, names []string) (bool, error) {
	hash := m.hashNames(names)
	if _, exists := m.fqdnSet[hash]; exists {
		return true, nil
	}
	return false, nil
}

// Return a map of domain -> certificate count.
func (m mockSAWithFQDNSet) CountCertificatesByNames(ctx context.Context, names []string, earliest, latest time.Time) (ret []*sapb.CountByNames_MapElement, err error) {
	var results []*sapb.CountByNames_MapElement
	for _, name := range names {
		if entry, ok := m.nameCounts[name]; ok {
			results = append(results, entry)
		}
	}
	return results, nil
}

func (m mockSAWithFQDNSet) CountFQDNSets(_ context.Context, _ time.Duration, names []string) (int64, error) {
	var count int64
	for _, name := range names {
		if entry, ok := m.nameCounts[name]; ok {
			count += *entry.Count
		}
	}
	return count, nil
}

// Tests for boulder issue 1925[0] - that the `checkCertificatesPerNameLimit`
// properly honours the FQDNSet exemption. E.g. that if a set of domains has
// reached the certificates per name rate limit policy threshold but the exact
// same set of FQDN's was previously issued, then it should not be considered
// over the certificates per name limit.
//
// [0] https://github.com/letsencrypt/boulder/issues/1925
func TestCheckFQDNSetRateLimitOverride(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Simple policy that only allows 1 certificate per name.
	certsPerNamePolicy := ratelimit.RateLimitPolicy{
		Threshold: 1,
		Window:    cmd.ConfigDuration{Duration: 24 * time.Hour},
	}

	// Create a mock SA that has both name counts and an FQDN set
	mockSA := &mockSAWithFQDNSet{
		nameCounts: map[string]*sapb.CountByNames_MapElement{
			"example.com": nameCount("example.com", 100),
			"zombo.com":   nameCount("zombo.com", 100),
		},
		fqdnSet: map[string]bool{},
		t:       t,
	}
	ra.SA = mockSA

	// First check that without a pre-existing FQDN set that the provided set of
	// names is rate limited due to being over the certificates per name limit for
	// "example.com" and "zombo.com"
	err := ra.checkCertificatesPerNameLimit(ctx, []string{"www.example.com", "example.com", "www.zombo.com"}, certsPerNamePolicy, 99)
	test.AssertError(t, err, "certificate per name rate limit not applied correctly")

	// Now add a FQDN set entry for these domains
	mockSA.addFQDNSet([]string{"www.example.com", "example.com", "www.zombo.com"})

	// A subsequent check against the certificates per name limit should now be OK
	// - there exists a FQDN set and so the exemption to this particular limit
	// comes into effect.
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"www.example.com", "example.com", "www.zombo.com"}, certsPerNamePolicy, 99)
	test.AssertNotError(t, err, "FQDN set certificate per name exemption not applied correctly")
}

// TestExactPublicSuffixCertLimit tests the behaviour of issue #2681 with and
// without the feature flag for the fix enabled.
// See https://github.com/letsencrypt/boulder/issues/2681
func TestExactPublicSuffixCertLimit(t *testing.T) {
	_, _, ra, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Simple policy that only allows 2 certificates per name.
	certsPerNamePolicy := ratelimit.RateLimitPolicy{
		Threshold: 2,
		Window:    cmd.ConfigDuration{Duration: 23 * time.Hour},
	}

	// We use "dedyn.io" and "dynv6.net" domains for the test on the implicit
	// assumption that both domains are present on the public suffix list.
	// Quickly verify that this is true before continuing with the rest of the test.
	_, err := publicsuffix.Domain("dedyn.io")
	test.AssertError(t, err, "dedyn.io was not on the public suffix list, invaliding the test")
	_, err = publicsuffix.Domain("dynv6.net")
	test.AssertError(t, err, "dynv6.net was not on the public suffix list, invaliding the test")

	// Back the mock SA with counts as if so far we have issued the following
	// certificates for the following domains:
	//   - test.dedyn.io (once)
	//   - test2.dedyn.io (once)
	//   - dynv6.net (twice)
	mockSA := &mockSAWithNameCounts{
		nameCounts: map[string]*sapb.CountByNames_MapElement{
			"dedyn.io":       nameCount("dedyn.io", 2),
			"test.dedyn.io":  nameCount("test.dedyn.io", 1),
			"test2.dedyn.io": nameCount("test2.dedyn.io", 1),
			"test3.dedyn.io": nameCount("test3.dedyn.io", 0),
		},
		exactCounts: map[string]*sapb.CountByNames_MapElement{
			"dedyn.io":  nameCount("dedyn.io", 0),
			"dynv6.net": nameCount("dynv6.net", 2),
		},
		clk: fc,
		t:   t,
	}
	ra.SA = mockSA

	// Trying to issue for "test3.dedyn.io" and "dedyn.io" should fail because the
	// CountCertificatesExact feature flag isn't enabled and there have been two
	// certificates issued for subdomains of dedyn.io
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"test3.dedyn.io", "dedyn.io"}, certsPerNamePolicy, 99)
	test.AssertError(t, err, "certificate per name rate limit not applied correctly")

	// Enable the CountCertificatesExact feature flag to allow the correct rate
	// limiting for exact PSL entry domains
	_ = features.Set(map[string]bool{"CountCertificatesExact": true})
	defer features.Reset()

	// Trying to issue for "test3.dedyn.io" and "dedyn.io" should succeed because
	// test3.dedyn.io has no certificates and "dedyn.io" is an exact public suffix
	// match with no certificates issued for it.
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"test3.dedyn.io", "dedyn.io"}, certsPerNamePolicy, 99)
	test.AssertNotError(t, err, "certificate per name rate limit not applied correctly")

	// Trying to issue for "test3.dedyn.io" and "dynv6.net" should fail because
	// "dynv6.net" is an exact public suffic match with 2 certificates issued for
	// it.
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"test3.dedyn.io", "dynv6.net"}, certsPerNamePolicy, 99)
	test.AssertError(t, err, "certificate per name rate limit not applied correctly")
}

// mockSAOnlyExact is a Mock SA that will fail all calls to
// CountCertifcatesByNames and will return 0 for all
// CountCertificatesByExactNames calls. It can be used to test that the correct
// function is called for a PSL matching domain
type mockSAOnlyExact struct {
	mocks.StorageAuthority
}

// CountCertificatesByNames for a mockSAOnlyExact will always fail
func (m mockSAOnlyExact) CountCertificatesByNames(_ context.Context, _ []string, _, _ time.Time) ([]*sapb.CountByNames_MapElement, error) {
	return nil, fmt.Errorf("mockSAOnlyExact had non-exact CountCertificatesByNames called")
}

// CountCertificatesByExactNames will always return 0 for every input name
func (m mockSAOnlyExact) CountCertificatesByExactNames(_ context.Context, names []string, _, _ time.Time) ([]*sapb.CountByNames_MapElement, error) {
	var results []*sapb.CountByNames_MapElement
	// For each name in the input, return a count of 0
	for _, name := range names {
		results = append(results, nameCount(name, 0))
	}
	return results, nil
}

// TestPSLMatchIssuance tests the conditions from Boulder issue #2758 in which
// the original CountCertificatesExact implementation would cause an RPC error
// if *only* an exact PSL matching domain was requested for issuance.
// https://github.com/letsencrypt/boulder/issues/2758
func TestPSLMatchIssuance(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Simple policy that only allows 2 certificates per name.
	certsPerNamePolicy := ratelimit.RateLimitPolicy{
		Threshold: 2,
		Window:    cmd.ConfigDuration{Duration: 23 * time.Hour},
	}

	// We use "dedyn.io" for the test on the implicit assumption that it is
	// present on the public suffix list. Quickly verify that this is true before
	// continuing with the rest of the test.
	_, err := publicsuffix.Domain("dedyn.io")
	test.AssertError(t, err, "dedyn.io was not on the public suffix list, invaliding the test")

	// Use a mock that will fail all calls to CountCertificatesByNames, only
	// supporting CountCertificatesByExactNames
	mockSA := &mockSAOnlyExact{}
	ra.SA = mockSA

	_ = features.Set(map[string]bool{"CountCertificatesExact": false})
	defer features.Reset()

	// Without CountCertificatesExact enabled we expect the rate limit check to
	// fail since it will use the in-exact SA method that the mock always fails
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"dedyn.io"}, certsPerNamePolicy, 99)
	test.AssertError(t, err, "exact PSL match certificate per name rate limit used wrong SA RPC")

	// Enable the CountCertificatesExact feature flag
	_ = features.Set(map[string]bool{"CountCertificatesExact": true})

	// With CountCertificatesExact enabled we expect the limit check to pass when
	// names only includes exact PSL matches and the RA will use the SA's exact
	// name lookup which the mock provides
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"dedyn.io"}, certsPerNamePolicy, 99)
	test.AssertNotError(t, err, "exact PSL match certificate per name rate limit used wrong SA RPC")
}

func TestDeactivateAuthorization(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	authz := core.Authorization{RegistrationID: 1}
	authz, err := sa.NewPendingAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Could not store test data")
	authz.Status = core.StatusValid
	err = sa.FinalizeAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Could not store test data")
	err = ra.DeactivateAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Could not deactivate authorization")
	deact, err := sa.GetAuthorization(ctx, authz.ID)
	test.AssertNotError(t, err, "Could not get deactivated authorization with ID "+authz.ID)
	test.AssertEquals(t, deact.Status, core.StatusDeactivated)
}

func TestDeactivateRegistration(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	err := ra.DeactivateRegistration(context.Background(), core.Registration{ID: 1})
	test.AssertError(t, err, "DeactivateRegistration failed with a non-valid registration")
	err = ra.DeactivateRegistration(context.Background(), core.Registration{ID: 1, Status: core.StatusDeactivated})
	test.AssertError(t, err, "DeactivateRegistration failed with a non-valid registration")
	err = ra.DeactivateRegistration(context.Background(), core.Registration{ID: 1, Status: core.StatusValid})
	test.AssertNotError(t, err, "DeactivateRegistration failed")
	dbReg, err := ra.SA.GetRegistration(context.Background(), 1)
	test.AssertNotError(t, err, "GetRegistration failed")
	test.AssertEquals(t, dbReg.Status, core.StatusDeactivated)
}

// noopCAA implements caaChecker, always returning nil
type noopCAA struct{}

func (cr noopCAA) IsCAAValid(
	ctx context.Context,
	in *vaPB.IsCAAValidRequest,
	opts ...grpc.CallOption,
) (*vaPB.IsCAAValidResponse, error) {
	return &vaPB.IsCAAValidResponse{}, nil
}

// caaRecorder implements caaChecker, always returning nil, but recording the
// names it was called for.
type caaRecorder struct {
	sync.Mutex
	names map[string]bool
}

func (cr *caaRecorder) IsCAAValid(
	ctx context.Context,
	in *vaPB.IsCAAValidRequest,
	opts ...grpc.CallOption,
) (*vaPB.IsCAAValidResponse, error) {
	cr.Lock()
	defer cr.Unlock()
	cr.names[*in.Domain] = true
	return &vaPB.IsCAAValidResponse{}, nil
}

// A mock SA that returns special authzs for testing rechecking of CAA (in
// TestRecheckCAADates below)
type mockSAWithRecentAndOlder struct {
	recent, older time.Time
	mocks.StorageAuthority
}

func (m *mockSAWithRecentAndOlder) GetValidAuthorizations(
	ctx context.Context,
	registrationID int64,
	names []string,
	now time.Time) (map[string]*core.Authorization, error) {
	makeIdentifier := func(name string) core.AcmeIdentifier {
		return core.AcmeIdentifier{
			Type:  core.IdentifierDNS,
			Value: name,
		}
	}
	return map[string]*core.Authorization{
		"recent.com": &core.Authorization{
			Identifier: makeIdentifier("recent.com"),
			Expires:    &m.recent,
			Challenges: []core.Challenge{{Status: core.StatusValid, Type: core.ChallengeTypeHTTP01}},
		},
		"older.com": &core.Authorization{
			Identifier: makeIdentifier("older.com"),
			Expires:    &m.older,
			Challenges: []core.Challenge{{Status: core.StatusValid, Type: core.ChallengeTypeHTTP01}},
		},
		"older2.com": &core.Authorization{
			Identifier: makeIdentifier("older2.com"),
			Expires:    &m.older,
			Challenges: []core.Challenge{{Status: core.StatusValid, Type: core.ChallengeTypeHTTP01}},
		},
		"wildcard.com": &core.Authorization{
			Identifier: makeIdentifier("wildcard.com"),
			Expires:    &m.older,
			Challenges: []core.Challenge{{Status: core.StatusValid, Type: core.ChallengeTypeHTTP01}},
		},
		"*.wildcard.com": &core.Authorization{
			Identifier: makeIdentifier("*.wildcard.com"),
			Expires:    &m.older,
			Challenges: []core.Challenge{{Status: core.StatusValid, Type: core.ChallengeTypeHTTP01}},
		},
	}, nil
}

// Test that the right set of domain names have their CAA rechecked, based on
// expiration time.
func TestRecheckCAADates(t *testing.T) {
	_, _, ra, fc, cleanUp := initAuthorities(t)
	defer cleanUp()
	recorder := &caaRecorder{names: make(map[string]bool)}
	ra.caa = recorder
	ra.authorizationLifetime = 15 * time.Hour
	ra.SA = &mockSAWithRecentAndOlder{
		recent: fc.Now().Add(15 * time.Hour),
		older:  fc.Now().Add(5 * time.Hour),
	}

	// NOTE: The names provided here correspond to authorizations in the
	// `mockSAWithRecentAndOlder`
	names := []string{"recent.com", "older.com", "older2.com", "wildcard.com", "*.wildcard.com"}
	err := ra.checkAuthorizations(context.Background(), names, 999)
	// We expect that there is no error rechecking authorizations for these names
	if err != nil {
		t.Errorf("expected nil err, got %s", err)
	}

	// We expect that "recent.com" is not checked because its mock authorization
	// isn't expired
	if _, present := recorder.names["recent.com"]; present {
		t.Errorf("Rechecked CAA unnecessarily for recent.com")
	}

	// We expect that "older.com" is checked
	if _, present := recorder.names["older.com"]; !present {
		t.Errorf("Failed to recheck CAA for older.com")
	}

	// We expect that "older2.com" is checked
	if _, present := recorder.names["older2.com"]; !present {
		t.Errorf("Failed to recheck CAA for older2.com")
	}

	// We expect that the "wildcard.com" domain (without the `*.` prefix) is checked.
	if _, present := recorder.names["wildcard.com"]; !present {
		t.Errorf("Failed to recheck CAA for wildcard.com")
	}

	// We expect that "*.wildcard.com" is checked (with the `*.` prefix, because
	// it is stripped at a lower layer than we are testing)
	if _, present := recorder.names["*.wildcard.com"]; !present {
		t.Errorf("Failed to recheck CAA for *.wildcard.com")
	}
}

type caaFailer struct{}

func (cf *caaFailer) IsCAAValid(
	ctx context.Context,
	in *vaPB.IsCAAValidRequest,
	opts ...grpc.CallOption,
) (*vaPB.IsCAAValidResponse, error) {
	name := *in.Domain
	if name == "a.com" {
		return nil, fmt.Errorf("Error checking CAA for a.com")
	} else if name == "c.com" {
		return nil, fmt.Errorf("Error checking CAA for c.com")
	}
	return &vaPB.IsCAAValidResponse{}, nil
}

func TestRecheckCAAEmpty(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	err := ra.recheckCAA(context.Background(), nil)
	if err != nil {
		t.Errorf("expected nil err, got %s", err)
	}
}

func TestRecheckCAASuccess(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	names := []string{"a.com", "b.com", "c.com"}
	err := ra.recheckCAA(context.Background(), names)
	if err != nil {
		t.Errorf("expected nil err, got %s", err)
	}
}

func TestRecheckCAAFail(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	names := []string{"a.com", "b.com", "c.com"}
	ra.caa = &caaFailer{}
	err := ra.recheckCAA(context.Background(), names)
	if err == nil {
		t.Errorf("expected err, got nil")
	} else if err.(*berrors.BoulderError).Type != berrors.CAA {
		t.Errorf("expected CAA error, got %v", err.(*berrors.BoulderError).Type)
	} else if !strings.Contains(err.Error(), "error rechecking CAA for a.com") {
		t.Errorf("expected error to contain error for a.com, got %q", err)
	} else if !strings.Contains(err.Error(), "error rechecking CAA for c.com") {
		t.Errorf("expected error to contain error for c.com, got %q", err)
	}
}

func TestNewOrder(t *testing.T) {
	// Only run under test/config-next config where 20170731115209_AddOrders.sql
	// has been applied
	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		return
	}

	_, _, ra, fc, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.orderLifetime = time.Hour

	id := int64(1)
	orderA, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: &id,
		Names:          []string{"b.com", "a.com", "a.com", "C.COM"},
	})
	test.AssertNotError(t, err, "ra.NewOrder failed")
	test.AssertEquals(t, *orderA.RegistrationID, int64(1))
	test.AssertEquals(t, *orderA.Expires, fc.Now().Add(time.Hour).UnixNano())
	test.AssertEquals(t, len(orderA.Names), 3)
	// We expect the order names to have been sorted, deduped, and lowercased
	test.AssertDeepEquals(t, orderA.Names, []string{"a.com", "b.com", "c.com"})
	test.AssertEquals(t, *orderA.Id, int64(1))
	test.AssertEquals(t, len(orderA.Authorizations), 3)

	// Reuse all existing authorizations
	orderB, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: &id,
		Names:          []string{"b.com", "a.com", "C.COM"},
	})
	test.AssertNotError(t, err, "ra.NewOrder failed")
	test.AssertEquals(t, *orderB.RegistrationID, int64(1))
	test.AssertEquals(t, *orderB.Expires, fc.Now().Add(time.Hour).UnixNano())
	// We expect orderB's ID to match orderA's because of pending order reuse
	test.AssertEquals(t, *orderB.Id, *orderA.Id)
	test.AssertEquals(t, len(orderB.Names), 3)
	test.AssertDeepEquals(t, orderB.Names, []string{"a.com", "b.com", "c.com"})
	test.AssertEquals(t, len(orderB.Authorizations), 3)
	sort.Strings(orderA.Authorizations)
	sort.Strings(orderB.Authorizations)
	test.AssertDeepEquals(t, orderB.Authorizations, orderA.Authorizations)

	// Reuse all of the existing authorizations from the previous order and
	// add a new one
	orderA.Names = append(orderA.Names, "d.com")
	orderC, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: &id,
		Names:          orderA.Names,
	})
	test.AssertNotError(t, err, "ra.NewOrder failed")
	test.AssertEquals(t, *orderC.RegistrationID, int64(1))
	test.AssertEquals(t, *orderC.Expires, fc.Now().Add(time.Hour).UnixNano())
	test.AssertEquals(t, len(orderC.Names), 4)
	test.AssertDeepEquals(t, orderC.Names, []string{"a.com", "b.com", "c.com", "d.com"})
	// We expect orderC's ID to not match orderA/orderB's because it is for
	// a different set of names
	test.AssertNotEquals(t, *orderC.Id, *orderA.Id)
	test.AssertEquals(t, len(orderC.Authorizations), 4)
	// Abuse the order of the queries used to extract the reused authorizations
	existing := orderC.Authorizations[:3]
	sort.Strings(existing)

	// We expect the pending authorizations were not reused between separate
	// orders
	// NOTE(@cpu): There's no test.AssertNotDeepEquals to use here so we call
	// reflect.DeepEqual ourselves.
	if reflect.DeepEqual(existing, orderA.Authorizations) {
		t.Fatal("existing authorizations matched orderA authorizations")
	}

	_, err = ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: &id,
		Names:          []string{"example.com", "a"},
	})
	test.AssertError(t, err, "NewOrder with invalid names did not error")
	test.AssertEquals(t, err.Error(), "DNS name does not have enough labels")
}

// TestNewOrderReuse tests that subsequent requests by an ACME account to create
// an identical order results in only one order being created & subsequently
// reused.
func TestNewOrderReuse(t *testing.T) {
	// Only run under test/config-next config where 20170731115209_AddOrders.sql
	// has been applied
	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		return
	}

	_, _, ra, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	ctx := context.Background()
	regA := int64(1)
	names := []string{"zombo.com", "welcome.to.zombo.com"}

	// Configure the RA to use a short order lifetime
	ra.orderLifetime = time.Hour
	// Create a var with two times the order lifetime to reference later
	doubleLifetime := ra.orderLifetime * 2

	// Create an initial request with regA and names
	orderReq := &rapb.NewOrderRequest{
		RegistrationID: &regA,
		Names:          names,
	}

	// Create a second registration to reference
	secondReg := core.Registration{
		Key:       &AccountKeyB,
		InitialIP: net.ParseIP("42.42.42.42"),
	}
	secondReg, err := ra.NewRegistration(ctx, secondReg)
	test.AssertNotError(t, err, "Error creating a second test registration")

	// First, add an order with `names` for regA
	firstOrder, err := ra.NewOrder(context.Background(), orderReq)
	// It shouldn't fail
	test.AssertNotError(t, err, "Adding an initial order for regA failed")
	// It should have an ID
	test.AssertNotNil(t, firstOrder.Id, "Initial order had a nil ID")

	testCases := []struct {
		Name         string
		OrderReq     *rapb.NewOrderRequest
		ExpectReuse  bool
		AdvanceClock *time.Duration
	}{
		{
			Name:     "Duplicate order, same regID",
			OrderReq: orderReq,
			// We expect reuse since the order matches firstOrder
			ExpectReuse: true,
		},
		{
			Name: "Subset of order names, same regID",
			OrderReq: &rapb.NewOrderRequest{
				RegistrationID: &regA,
				Names:          []string{names[1]},
			},
			// We do not expect reuse because the order names don't match firstOrder
			ExpectReuse: false,
		},
		{
			Name: "Duplicate order, different regID",
			OrderReq: &rapb.NewOrderRequest{
				RegistrationID: &secondReg.ID,
				Names:          names,
			},
			// We do not expect reuse because the order regID differs from firstOrder
			ExpectReuse: false,
		},
		{
			Name:         "Duplicate order, same regID, first expired",
			OrderReq:     orderReq,
			AdvanceClock: &doubleLifetime,
			// We do not expect reuse because firstOrder has expired
			ExpectReuse: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// If the testcase specifies, advance the clock before adding the order
			if tc.AdvanceClock != nil {
				fc.Now().Add(*tc.AdvanceClock)
			}
			// Add the order for the test request
			order, err := ra.NewOrder(ctx, tc.OrderReq)
			// It shouldn't fail
			test.AssertNotError(t, err, "NewOrder returned an unexpected error")
			// The order should not have a nil ID
			test.AssertNotNil(t, order.Id, "NewOrder returned an order with a nil Id")

			if tc.ExpectReuse {
				// If we expected order reuse for this testcase assert that the order
				// has the same ID as the firstOrder
				test.AssertEquals(t, *firstOrder.Id, *order.Id)
			} else {
				// Otherwise assert that the order doesn't have the same ID as the
				// firstOrder
				test.AssertNotEquals(t, *firstOrder.Id, *order.Id)
			}
		})
	}
}

func TestNewOrderReuseInvalidAuthz(t *testing.T) {
	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		return
	}

	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	ctx := context.Background()
	regA := int64(1)
	names := []string{"zombo.com"}

	// Create an initial request with regA and names
	orderReq := &rapb.NewOrderRequest{
		RegistrationID: &regA,
		Names:          names,
	}

	// First, add an order with `names` for regA
	order, err := ra.NewOrder(ctx, orderReq)
	// It shouldn't fail
	test.AssertNotError(t, err, "Adding an initial order for regA failed")
	// It should have an ID
	test.AssertNotNil(t, order.Id, "Initial order had a nil ID")
	// It should have one authorization
	test.AssertEquals(t, len(order.Authorizations), 1)

	// Fetch the full authz by the ID
	authzID := order.Authorizations[0]
	authz, err := ra.SA.GetAuthorization(ctx, authzID)
	test.AssertNotError(t, err, "Error getting order authorization")

	// Finalize the authz to an invalid status
	authz.Status = core.StatusInvalid
	err = ra.SA.FinalizeAuthorization(ctx, authz)
	test.AssertNotError(t, err, fmt.Sprintf("Could not finalize authorization %q", authzID))

	// The order associated with the authz should now be invalid
	updatedOrder, err := ra.SA.GetOrder(ctx, &sapb.OrderRequest{Id: order.Id})
	test.AssertNotError(t, err, "Error getting order to check status")
	test.AssertEquals(t, *updatedOrder.Status, "invalid")

	// Create a second order for the same names/regID
	secondOrder, err := ra.NewOrder(ctx, orderReq)
	// It shouldn't fail
	test.AssertNotError(t, err, "Adding an initial order for regA failed")
	// It should have a different ID than the first now-invalid order
	test.AssertNotEquals(t, *secondOrder.Id, *order.Id)
	// It should be status pending
	test.AssertEquals(t, *secondOrder.Status, "pending")
	// It should have one authorization
	test.AssertEquals(t, len(secondOrder.Authorizations), 1)
	// It should have a different authorization than the first order's now-invalid authorization
	test.AssertNotEquals(t, secondOrder.Authorizations[0], order.Authorizations[0])
}

func TestNewOrderWildcard(t *testing.T) {
	// Only run under test/config-next config where 20170731115209_AddOrders.sql
	// has been applied
	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		return
	}

	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.orderLifetime = time.Hour
	id := int64(1)

	orderNames := []string{"example.com", "*.welcome.zombo.com"}
	wildcardOrderRequest := &rapb.NewOrderRequest{
		RegistrationID: &id,
		Names:          orderNames,
	}

	// First test that with WildcardDomains feature disabled wildcard orders are
	// rejected as expected
	_ = features.Set(map[string]bool{"WildcardDomains": false})

	_, err := ra.NewOrder(context.Background(), wildcardOrderRequest)
	test.AssertError(t, err, "NewOrder with wildcard names did not error with "+
		"WildcardDomains feature disabled")
	test.AssertEquals(t, err.Error(), "Invalid character in DNS name")

	// Now test with WildcardDomains feature enabled
	features.Reset()
	_ = features.Set(map[string]bool{"WildcardDomains": true})
	defer features.Reset()

	// Also ensure that the required challenge types are enabled. The ra_test
	// global `SupportedChallenges` used by `initAuthorities` does not include
	// DNS-01
	supportedChallenges := map[string]bool{
		core.ChallengeTypeHTTP01:   true,
		core.ChallengeTypeTLSSNI01: true,
		core.ChallengeTypeDNS01:    true,
	}
	pa, err := policy.New(supportedChallenges)
	test.AssertNotError(t, err, "Couldn't create PA")
	err = pa.SetHostnamePolicyFile("../test/hostname-policy.json")
	test.AssertNotError(t, err, "Couldn't set hostname policy")
	ra.PA = pa

	order, err := ra.NewOrder(context.Background(), wildcardOrderRequest)
	test.AssertNotError(t, err, "NewOrder failed for a wildcard order request "+
		"with WildcardDomains enabled")

	// We expect the order to be pending
	test.AssertEquals(t, *order.Status, string(core.StatusPending))
	// We expect the order to have two names
	test.AssertEquals(t, len(order.Names), 2)
	// We expect the order to have the names we requested
	test.AssertDeepEquals(t,
		core.UniqueLowerNames(order.Names),
		core.UniqueLowerNames(orderNames))
	// We expect the order to have two authorizations
	test.AssertEquals(t, len(order.Authorizations), 2)

	// Check each of the authz IDs in the order
	for _, authzID := range order.Authorizations {
		// We should be able to retreive the authz from the db without error
		authz, err := ra.SA.GetAuthorization(ctx, authzID)
		test.AssertNotError(t, err, "Could not fetch authorization from database")

		// We expect the authz is in Pending status
		test.AssertEquals(t, authz.Status, core.StatusPending)

		name := authz.Identifier.Value
		switch name {
		case "*.welcome.zombo.com":
			// If the authz is for *.welcome.zombo.com, we expect that it only has one
			// pending challenge with DNS-01 type
			test.AssertEquals(t, len(authz.Challenges), 1)
			test.AssertEquals(t, authz.Challenges[0].Status, core.StatusPending)
			test.AssertEquals(t, authz.Challenges[0].Type, core.ChallengeTypeDNS01)
		case "example.com":
			// If the authz is for example.com, we expect it has normal challenges
			test.AssertEquals(t, len(authz.Challenges), 3)
		default:
			t.Fatalf("Received an authorization for a name not requested: %q", name)
		}
	}

	// An order for a base domain and a wildcard for the same base domain should
	// return just 2 authz's, one for the wildcard with a DNS-01
	// challenge and one for the base domain with the normal challenges.
	orderNames = []string{"zombo.com", "*.zombo.com"}
	wildcardOrderRequest = &rapb.NewOrderRequest{
		RegistrationID: &id,
		Names:          orderNames,
	}
	order, err = ra.NewOrder(context.Background(), wildcardOrderRequest)
	test.AssertNotError(t, err, "NewOrder failed for a wildcard order request "+
		"with WildcardDomains enabled")

	// We expect the order to be pending
	test.AssertEquals(t, *order.Status, string(core.StatusPending))
	// We expect the order to have two names
	test.AssertEquals(t, len(order.Names), 2)
	// We expect the order to have the names we requested
	test.AssertDeepEquals(t,
		core.UniqueLowerNames(order.Names),
		core.UniqueLowerNames(orderNames))
	// We expect the order to have two authorizations
	test.AssertEquals(t, len(order.Authorizations), 2)

	for _, authzID := range order.Authorizations {
		// We expect the authorization is available
		authz, err := ra.SA.GetAuthorization(ctx, authzID)
		test.AssertNotError(t, err, "Could not fetch authorization from database")
		// We expect the authz is in Pending status
		test.AssertEquals(t, authz.Status, core.StatusPending)
		switch authz.Identifier.Value {
		case "zombo.com":
			// We expect that the base domain identifier auth has the normal number of
			// challenges
			test.AssertEquals(t, len(authz.Challenges), 3)
		case "*.zombo.com":
			// We expect that the wildcard identifier auth has only a pending
			// DNS-01 type challenge
			test.AssertEquals(t, len(authz.Challenges), 1)
			test.AssertEquals(t, authz.Challenges[0].Status, core.StatusPending)
			test.AssertEquals(t, authz.Challenges[0].Type, core.ChallengeTypeDNS01)
		default:
			t.Fatal("Unexpected authorization value returned from new-order")
		}
	}

	// Make an order for a single domain, no wildcards. This will create a new
	// pending authz for the domain
	normalOrderReq := &rapb.NewOrderRequest{
		RegistrationID: &id,
		Names:          []string{"everything.is.possible.zombo.com"},
	}
	normalOrder, err := ra.NewOrder(context.Background(), normalOrderReq)
	test.AssertNotError(t, err, "NewOrder failed for a normal non-wildcard order")

	// There should be one authz
	test.AssertEquals(t, len(normalOrder.Authorizations), 1)
	// We expect the order is in Pending status
	test.AssertEquals(t, *order.Status, string(core.StatusPending))
	// We expect the authorization is available
	authz, err := ra.SA.GetAuthorization(ctx, normalOrder.Authorizations[0])
	test.AssertNotError(t, err, "Could not fetch authorization from database")
	// We expect the authz is in Pending status
	test.AssertEquals(t, authz.Status, core.StatusPending)
	// We expect the authz is for the identifier the correct domain
	test.AssertEquals(t, authz.Identifier.Value, "everything.is.possible.zombo.com")
	// We expect the authz has the normal # of challenges
	test.AssertEquals(t, len(authz.Challenges), 3)

	// Now submit an order request for a wildcard of the domain we just created an
	// order for. We should **NOT** reuse the authorization from the previous
	// order since we now require a DNS-01 challenge for the `*.` prefixed name.
	orderNames = []string{"*.everything.is.possible.zombo.com"}
	wildcardOrderRequest = &rapb.NewOrderRequest{
		RegistrationID: &id,
		Names:          orderNames,
	}
	order, err = ra.NewOrder(context.Background(), wildcardOrderRequest)
	test.AssertNotError(t, err, "NewOrder failed for a wildcard order request "+
		"with WildcardDomains enabled")
	// We expect the order is in Pending status
	test.AssertEquals(t, *order.Status, string(core.StatusPending))
	// There should be one authz
	test.AssertEquals(t, len(order.Authorizations), 1)
	// The authz should be a different ID than the previous authz
	test.AssertNotEquals(t, order.Authorizations[0], normalOrder.Authorizations[0])
	// We expect the authorization is available
	authz, err = ra.SA.GetAuthorization(ctx, order.Authorizations[0])
	test.AssertNotError(t, err, "Could not fetch authorization from database")
	// We expect the authz is in Pending status
	test.AssertEquals(t, authz.Status, core.StatusPending)
	// We expect the authz is for a identifier with the correct domain
	test.AssertEquals(t, authz.Identifier.Value, "*.everything.is.possible.zombo.com")
	// We expect the authz has only one challenge
	test.AssertEquals(t, len(authz.Challenges), 1)
	// We expect the one challenge is pending
	test.AssertEquals(t, authz.Challenges[0].Status, core.StatusPending)
	// We expect that the one challenge is a DNS01 type challenge
	test.AssertEquals(t, authz.Challenges[0].Type, core.ChallengeTypeDNS01)

	// Submit an identical wildcard order request
	dupeOrder, err := ra.NewOrder(context.Background(), wildcardOrderRequest)
	test.AssertNotError(t, err, "NewOrder failed for a wildcard order request "+
		"with WildcardDomains enabled")
	// We expect the order is in Pending status
	test.AssertEquals(t, *dupeOrder.Status, string(core.StatusPending))
	// There should be one authz
	test.AssertEquals(t, len(dupeOrder.Authorizations), 1)
	// The authz should be the same ID as the previous order's authz. We already
	// checked that order.Authorizations[0] only has a DNS-01 challenge above so
	// we don't need to recheck that here.
	test.AssertEquals(t, dupeOrder.Authorizations[0], order.Authorizations[0])
}

func TestFinalizeOrder(t *testing.T) {
	// Only run under test/config-next config where 20170731115209_AddOrders.sql
	// has been applied
	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		return
	}

	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.orderLifetime = time.Hour

	validStatus := "valid"

	testKey, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "error generating test key")
	policyForbidCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		PublicKey:          testKey.PublicKey,
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           []string{"example.org"},
	}, testKey)
	test.AssertNotError(t, err, "Error creating policy forbid CSR")

	oneDomainCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		PublicKey:          testKey.PublicKey,
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           []string{"example.com"},
	}, testKey)
	test.AssertNotError(t, err, "Error creating CSR with one DNS name")

	twoDomainCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		PublicKey:          testKey.PublicKey,
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           []string{"a.com", "a.org"},
	}, testKey)
	test.AssertNotError(t, err, "Error creating CSR with two DNS names")

	threeDomainCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		PublicKey:          testKey.PublicKey,
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           []string{"a.com", "a.org", "b.com"},
	}, testKey)
	test.AssertNotError(t, err, "Error creating CSR with three DNS names")

	// Pick an expiry in the future
	exp := ra.clk.Now().Add(365 * 24 * time.Hour)

	// Create one finalized authorization for Registration.ID for not-example.com
	finalAuthz := AuthzInitial
	finalAuthz.Identifier = core.AcmeIdentifier{Type: "dns", Value: "not-example.com"}
	finalAuthz.Status = "valid"
	finalAuthz.Expires = &exp
	finalAuthz.Challenges[0].Status = "valid"
	finalAuthz.RegistrationID = Registration.ID
	finalAuthz, err = sa.NewPendingAuthorization(ctx, finalAuthz)
	test.AssertNotError(t, err, "Could not store test pending authorization")
	err = sa.FinalizeAuthorization(ctx, finalAuthz)
	test.AssertNotError(t, err, "Could not finalize test pending authorization")

	// Create one finalized authorization for Registration.ID for www.not-example.org
	finalAuthzB := AuthzInitial
	finalAuthzB.Identifier = core.AcmeIdentifier{Type: "dns", Value: "www.not-example.com"}
	finalAuthzB.Status = "valid"
	finalAuthzB.Expires = &exp
	finalAuthzB.Challenges[0].Status = "valid"
	finalAuthzB.RegistrationID = Registration.ID
	finalAuthzB, err = sa.NewPendingAuthorization(ctx, finalAuthzB)
	test.AssertNotError(t, err, "Could not store 2nd test pending authorization")
	err = sa.FinalizeAuthorization(ctx, finalAuthzB)
	test.AssertNotError(t, err, "Could not finalize 2nd test pending authorization")

	// Create a new order referencing both of the above finalized authzs
	pendingStatus := "pending"
	expUnix := exp.Unix()
	finalOrder, err := sa.NewOrder(context.Background(), &corepb.Order{
		RegistrationID: &Registration.ID,
		Expires:        &expUnix,
		Names:          []string{"not-example.com", "www.not-example.com"},
		Authorizations: []string{finalAuthz.ID, finalAuthzB.ID},
		Status:         &pendingStatus,
	})
	test.AssertNotError(t, err, "Could not add test order with finalized authz IDs")

	// Swallowing errors here because the CSRPEM is hardcoded test data expected
	// to parse in all instance
	validCSRBlock, _ := pem.Decode(CSRPEM)
	validCSR, _ := x509.ParseCertificateRequest(validCSRBlock.Bytes)

	fakeRegID := int64(0xB00)

	// NOTE(@cpu): We use unique `names` for each of these orders because
	// otherwise only *one* order is created & reused. The first test case to
	// finalize the order will put it into processing state and the other tests
	// will fail because you can't finalize an order that is already being
	// processed.
	emptyOrder, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: &Registration.ID,
		Names:          []string{"000.example.com"},
	})
	test.AssertNotError(t, err, "Could not add test order for fake order ID")

	// Add a new order for the fake reg ID
	fakeRegOrder, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: &Registration.ID,
		Names:          []string{"001.example.com"},
	})
	test.AssertNotError(t, err, "Could not add test order for fake reg ID order ID")

	missingAuthzOrder, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: &Registration.ID,
		Names:          []string{"002.example.com"},
	})
	test.AssertNotError(t, err, "Could not add test order for missing authz order ID")

	testCases := []struct {
		Name           string
		OrderReq       *rapb.FinalizeOrderRequest
		ExpectedErrMsg string
		ExpectIssuance bool
	}{
		{
			Name: "No names in order",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Status: &pendingStatus,
					Names:  []string{},
				},
			},
			ExpectedErrMsg: "Order has no associated names",
		},
		{
			Name: "Wrong order state",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Status: &validStatus,
					Names:  []string{"example.com"},
				},
			},
			ExpectedErrMsg: "Order's status (\"valid\") was not pending",
		},
		{
			Name: "Invalid CSR",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Status: &pendingStatus,
					Names:  []string{"example.com"},
				},
				Csr: []byte{0xC0, 0xFF, 0xEE},
			},
			ExpectedErrMsg: "asn1: syntax error: truncated tag or length",
		},
		{
			Name: "CSR and Order with diff number of names",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Status:         &pendingStatus,
					Names:          []string{"example.com", "example.org"},
					RegistrationID: &fakeRegID,
				},
				Csr: oneDomainCSR,
			},
			ExpectedErrMsg: "Order includes different number of names than CSR specifies",
		},
		{
			Name: "CSR missing an order name",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Status:         &pendingStatus,
					Names:          []string{"foobar.com"},
					RegistrationID: &fakeRegID,
				},
				Csr: oneDomainCSR,
			},
			ExpectedErrMsg: "CSR is missing Order domain \"foobar.com\"",
		},
		{
			Name: "CSR with policy forbidden name",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Status:         &pendingStatus,
					Names:          []string{"example.org"},
					RegistrationID: &Registration.ID,
					Id:             emptyOrder.Id,
				},
				Csr: policyForbidCSR,
			},
			ExpectedErrMsg: "policy forbids issuing for: \"example.org\"",
		},
		{
			Name: "Order with missing registration",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Status:         &pendingStatus,
					Names:          []string{"a.com", "a.org"},
					Id:             fakeRegOrder.Id,
					RegistrationID: &fakeRegID,
				},
				Csr: twoDomainCSR,
			},
			ExpectedErrMsg: fmt.Sprintf("registration with ID '%d' not found", fakeRegID),
		},
		{
			Name: "Order with missing authorizations",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Status:         &pendingStatus,
					Names:          []string{"a.com", "a.org", "b.com"},
					Id:             missingAuthzOrder.Id,
					RegistrationID: &Registration.ID,
				},
				Csr: threeDomainCSR,
			},
			ExpectedErrMsg: "authorizations for these names not found or expired: a.com, a.org, b.com",
		},
		{
			Name: "Order with correct authorizations",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: finalOrder,
				Csr:   validCSR.Raw,
			},
			ExpectIssuance: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			_, result := ra.FinalizeOrder(context.Background(), tc.OrderReq)
			// If we don't expect issuance we expect an error
			if !tc.ExpectIssuance {
				// Check that the error happened and the message matches expected
				test.AssertError(t, result, "FinalizeOrder did not fail when expected to")
				test.AssertEquals(t, result.Error(), tc.ExpectedErrMsg)
			} else {
				// Otherwise we expect an issuance and no error
				test.AssertNotError(t, result, fmt.Sprintf("FinalizeOrder result was %#v, expected nil", result))
				// Check that the order now has a serial for the issued certificate
				updatedOrder, err := sa.GetOrder(
					context.Background(),
					&sapb.OrderRequest{Id: tc.OrderReq.Order.Id})
				test.AssertNotError(t, err, "Error getting order to check serial")
				test.AssertNotEquals(t, *updatedOrder.CertificateSerial, "")
				test.AssertEquals(t, *updatedOrder.Status, "valid")
			}
		})
	}
}

func TestFinalizeOrderWildcard(t *testing.T) {
	// Only run under test/config-next config where 20170731115209_AddOrders.sql
	// has been applied
	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		return
	}

	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Pick an expiry in the future
	exp := ra.clk.Now().Add(365 * 24 * time.Hour)

	// Enable wildcard domains
	_ = features.Set(map[string]bool{"WildcardDomains": true})
	defer features.Reset()

	// Also ensure that the required challenge types are enabled. The ra_test
	// global `SupportedChallenges` used by `initAuthorities` does not include
	// DNS-01 or DNS-01-Wildcard
	supportedChallenges := map[string]bool{
		core.ChallengeTypeHTTP01:   true,
		core.ChallengeTypeTLSSNI01: true,
		core.ChallengeTypeDNS01:    true,
	}
	pa, err := policy.New(supportedChallenges)
	test.AssertNotError(t, err, "Couldn't create PA")
	err = pa.SetHostnamePolicyFile("../test/hostname-policy.json")
	test.AssertNotError(t, err, "Couldn't set hostname policy")
	ra.PA = pa

	testKey, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "Error creating test RSA key")
	wildcardCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		PublicKey:          testKey.PublicKey,
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           []string{"*.zombo.com"},
	}, testKey)
	test.AssertNotError(t, err, "Error creating CSR with wildcard DNS name")

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1337),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 1),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"*.zombo.com"},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, testKey.Public(), testKey)
	test.AssertNotError(t, err, "Error creating test certificate")

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Set up a mock CA capable of giving back a cert for the wildcardCSR above
	ca := &mocks.MockCA{
		PEM: certPEM,
	}
	ra.CA = ca

	// Create a new order for a wildcard domain
	orderNames := []string{"*.zombo.com"}
	wildcardOrderRequest := &rapb.NewOrderRequest{
		RegistrationID: &Registration.ID,
		Names:          orderNames,
	}
	order, err := ra.NewOrder(context.Background(), wildcardOrderRequest)
	test.AssertNotError(t, err, "NewOrder failed for wildcard domain order")

	// Create one standard finalized authorization for Registration.ID for zombo.com
	finalAuthz := AuthzInitial
	finalAuthz.Identifier = core.AcmeIdentifier{Type: "dns", Value: "zombo.com"}
	finalAuthz.Status = "valid"
	finalAuthz.Expires = &exp
	finalAuthz.Challenges[0].Status = "valid"
	finalAuthz.RegistrationID = Registration.ID
	finalAuthz, err = sa.NewPendingAuthorization(ctx, finalAuthz)
	test.AssertNotError(t, err, "Could not store test pending authorization")
	err = sa.FinalizeAuthorization(ctx, finalAuthz)
	test.AssertNotError(t, err, "Could not finalize test pending authorization")

	// Finalizing the order should *not* work since the existing validated authz
	// is not a special DNS-01-Wildcard challenge authz
	finalizeReq := &rapb.FinalizeOrderRequest{
		Order: order,
		Csr:   wildcardCSR,
	}
	_, err = ra.FinalizeOrder(context.Background(), finalizeReq)
	test.AssertError(t, err, "FinalizeOrder did not fail for unauthorized "+
		"wildcard order")
	test.AssertEquals(t, err.Error(), "authorizations for these names not "+
		"found or expired: *.zombo.com")

	// Creating another order for the wildcard name
	validOrder, err := ra.NewOrder(context.Background(), wildcardOrderRequest)
	test.AssertNotError(t, err, "NewOrder failed for wildcard domain order")
	// We expect it has 1 authorization
	test.AssertEquals(t, len(validOrder.Authorizations), 1)
	// We expect to be able to get the authorization by ID
	authz, err := sa.GetAuthorization(ctx, validOrder.Authorizations[0])
	test.AssertNotError(t, err, "GetAuthorization failed for order authz ID")

	// Finalize the authorization with the challenge validated
	authz.Status = "valid"
	authz.Challenges[0].Status = "valid"
	err = sa.FinalizeAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Could not finalize order's pending authorization")

	// Now it should be possible to finalize the order
	finalizeReq = &rapb.FinalizeOrderRequest{
		Order: validOrder,
		Csr:   wildcardCSR,
	}
	_, err = ra.FinalizeOrder(context.Background(), finalizeReq)
	test.AssertNotError(t, err, "FinalizeOrder failed for authorized "+
		"wildcard order")
}

// TestUpdateMissingAuthorization tests the race condition where a challenge is
// updated to valid concurrently with another attempt to have the challenge
// updated. Previously this would return a `berrors.InternalServer` error when
// the row was found missing from `pendingAuthorizations` by the 2nd update
// since the 1st had already deleted it. We accept this may happen and now test
// for a `berrors.NotFound` error return.
//
// See https://github.com/letsencrypt/boulder/issues/3201
func TestUpdateMissingAuthorization(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	ctx := context.Background()

	authz, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization failed")

	// Twiddle the authz to pretend its been validated by the VA
	authz.Status = "valid"
	authz.Challenges[0].Status = "valid"

	// Call onValidationUpdate once to finalize the new authz state with the SA.
	// It should not error
	err = ra.onValidationUpdate(ctx, authz)
	test.AssertNotError(t, err, "Initial onValidationUpdate for Authz failed")

	// Call onValidationUpdate again to simulate another validation attempt
	// finishing. It should error since the pendingAuthorization row has been
	// removed by the first finalization update.
	err = ra.onValidationUpdate(ctx, authz)
	test.AssertError(t, err, "Second onValidationUpdate didn't fail")
	// It should *not* be an internal server error
	test.AssertEquals(t, berrors.Is(err, berrors.InternalServer), false)
	// It *should* be a NotFound error
	test.AssertEquals(t, berrors.Is(err, berrors.NotFound), true)
}

var previousIssuanceRegId int64 = 98765
var previousIssuanceDomain string = "example.com"

// mockSAPreexistingCertificate acts as an SA that has an existing certificate
// for "example.com".
type mockSAPreexistingCertificate struct {
	mocks.StorageAuthority
}

func (ms *mockSAPreexistingCertificate) PreviousCertificateExists(ctx context.Context, req *sapb.PreviousCertificateExistsRequest) (*sapb.Exists, error) {
	t := true
	f := false
	if *req.RegID == previousIssuanceRegId &&
		*req.Domain == previousIssuanceDomain {
		return &sapb.Exists{Exists: &t}, nil
	}
	return &sapb.Exists{Exists: &f}, nil
}

// With TLS-SNI-01 disabled, an account that previously issued a certificate for
// example.com should still be able to get a new authorization.
func TestNewAuthzTLSSNIRevalidation(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	challenges := map[string]bool{
		core.ChallengeTypeHTTP01: true,
	}
	_ = features.Set(map[string]bool{
		"EnforceChallengeDisable": true,
		"TLSSNIRevalidation":      true,
	})
	pa, err := policy.New(challenges)
	test.AssertNotError(t, err, "Couldn't create PA")
	err = pa.SetHostnamePolicyFile("../test/hostname-policy.json")
	test.AssertNotError(t, err, "Couldn't set hostname policy")
	ra.PA = pa

	ra.SA = &mockSAPreexistingCertificate{}

	// Test with a reg ID and hostname that have a previous issuance, expect to
	// see TLS-SNI-01.
	authz, err := ra.NewAuthorization(context.Background(),
		core.Authorization{
			Identifier: core.AcmeIdentifier{
				Type:  core.IdentifierDNS,
				Value: previousIssuanceDomain,
			},
		}, previousIssuanceRegId)
	test.AssertNotError(t, err, "creating authz with domain for revalidation")

	hasTLSSNI := func(challenges []core.Challenge) bool {
		var foundTLSSNI bool
		for _, c := range challenges {
			if c.Type == core.ChallengeTypeTLSSNI01 {
				foundTLSSNI = true
			}
		}
		return foundTLSSNI
	}
	if !hasTLSSNI(authz.Challenges) {
		t.Errorf("TLS-SNI challenge was not created during revalidation.")
	}

	// Test with a different reg ID, expect no TLS-SNI-01.
	authz, err = ra.NewAuthorization(context.Background(),
		core.Authorization{
			Identifier: core.AcmeIdentifier{
				Type:  core.IdentifierDNS,
				Value: previousIssuanceDomain,
			},
		}, 1234)
	test.AssertNotError(t, err, "creating authz with domain for revalidation")
	if hasTLSSNI(authz.Challenges) {
		t.Errorf("TLS-SNI challenge was created during non-revalidation new-authz " +
			"(different regID).")
	}

	// Test with a different domain, expect no TLS-SNI-01.
	authz, err = ra.NewAuthorization(context.Background(),
		core.Authorization{
			Identifier: core.AcmeIdentifier{
				Type:  core.IdentifierDNS,
				Value: "not.example.com",
			},
		}, previousIssuanceRegId)
	test.AssertNotError(t, err, "creating authz with domain for revalidation")
	if hasTLSSNI(authz.Challenges) {
		t.Errorf("TLS-SNI challenge was created during non-revalidation new-authz " +
			"(different domain).")
	}
}

func TestValidChallengeStillGood(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	pa, err := policy.New(map[string]bool{
		core.ChallengeTypeTLSSNI01: true,
	})
	test.AssertNotError(t, err, "Couldn't create PA")
	ra.PA = pa

	_ = features.Set(map[string]bool{"EnforceChallengeDisable": true})

	test.Assert(t, !ra.authzValidChallengeEnabled(&core.Authorization{}), "ra.authzValidChallengeEnabled didn't fail with empty authorization")
	test.Assert(t, !ra.authzValidChallengeEnabled(&core.Authorization{Challenges: []core.Challenge{{Status: core.StatusPending}}}), "ra.authzValidChallengeEnabled didn't fail with no valid challenges")
	test.Assert(t, !ra.authzValidChallengeEnabled(&core.Authorization{Challenges: []core.Challenge{{Status: core.StatusValid, Type: core.ChallengeTypeHTTP01}}}), "ra.authzValidChallengeEnabled didn't fail with disabled challenge")

	test.Assert(t, ra.authzValidChallengeEnabled(&core.Authorization{Challenges: []core.Challenge{{Status: core.StatusValid, Type: core.ChallengeTypeTLSSNI01}}}), "ra.authzValidChallengeEnabled failed with enabled challenge")
}

func TestUpdateAuthorizationBadChallengeType(t *testing.T) {
	_, _, ra, fc, cleanUp := initAuthorities(t)
	defer cleanUp()
	pa, err := policy.New(map[string]bool{})
	test.AssertNotError(t, err, "Couldn't create PA")
	ra.PA = pa

	_ = features.Set(map[string]bool{"EnforceChallengeDisable": true})

	exp := fc.Now().Add(10 * time.Hour)
	_, err = ra.UpdateAuthorization(context.Background(), core.Authorization{Challenges: []core.Challenge{{Status: core.StatusValid, Type: core.ChallengeTypeTLSSNI01}}, Expires: &exp}, 0, core.Challenge{})
	test.AssertError(t, err, "ra.UpdateAuthorization allowed a update to a authorization")
	test.AssertEquals(t, err.Error(), "challenge type \"tls-sni-01\" no longer allowed")
}

var CAkeyPEM = `
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`

var CAcertPEM = `
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
`

// CSR generated by Go:
// * Random public key
// * CN = not-example.com
// * DNSNames = not-example.com, www.not-example.com
var CSRPEM = []byte(`
-----BEGIN CERTIFICATE REQUEST-----
MIICrjCCAZYCAQAwJzELMAkGA1UEBhMCVVMxGDAWBgNVBAMTD25vdC1leGFtcGxl
LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKT1B7UsonZuLOp7
qq2pw+COo0I9ZheuhN9ltu1+bAMWBYUb8KFPNGGp8Ygt6YCLjlnWOche7Fjb5lPj
hV6U2BkEt85mdaGTDg6mU3qjk2/cnZeAvJWW5ewYOBGxN/g/KHgdYZ+uhHH/PbGt
Wktcv5bRJ9Dxbjxsy7l8SLQ6fd/MF/3z6sBJzIHkcDupDOFdPN/Z0KOw7BOPHAbg
ghLJTmiESA1Ljxb8848bENlCz8pVizIu2Ilr4xBPtA5oUfO0FJKbT1T66JZoqwy/
drfrlHA7F6c8kYlAmwiOfWHzlWCkE1YuZPJrZQrt4tJ70rrPxV1qEGJDumzgcEbU
/aYYiBsCAwEAAaBCMEAGCSqGSIb3DQEJDjEzMDEwLwYDVR0RBCgwJoIPbm90LWV4
YW1wbGUuY29tghN3d3cubm90LWV4YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IB
AQBuFo5SHqN1lWmM6rKaOBXFezAdzZyGb9x8+5Zq/eh9pSxpn0MTOmq/u+sDHxsC
ywcshUO3P9//9u4ALtNn/jsJmSrElsTvG3SH5owl9muNEiOgf+6/rY/X8Zcnv/e0
Ar9r73BcCkjoAOFbr7xiLLYu5EaBQjSj6/m4ujwJTWS2SqobK5VfdpzmDp4wT3eB
V4FPLxyxxOLuWLzcBkDdLw/zh922HtR5fqk155Y4pj3WS9NnI/NMHmclrlfY/2P4
dJrBVM+qVbPTzM19QplMkiy7FxpDx6toUXDYM4KdKKV0+yX/zw/V0/Gb7K7yIjVB
wqjllqgMjN4nvHjiDXFx/kPY
-----END CERTIFICATE REQUEST-----
`)

var eeCertPEM = []byte(`
-----BEGIN CERTIFICATE-----
MIIEfTCCAmWgAwIBAgISCr9BRk0C9OOGVke6CAa8F+AXMA0GCSqGSIb3DQEBCwUA
MDExCzAJBgNVBAYTAlVTMRAwDgYDVQQKDAdUZXN0IENBMRAwDgYDVQQDDAdUZXN0
IENBMB4XDTE2MDMyMDE4MTEwMFoXDTE2MDMyMDE5MTEwMFowHjEcMBoGA1UEAxMT
d3d3Lm5vdC1leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAKT1B7UsonZuLOp7qq2pw+COo0I9ZheuhN9ltu1+bAMWBYUb8KFPNGGp8Ygt
6YCLjlnWOche7Fjb5lPjhV6U2BkEt85mdaGTDg6mU3qjk2/cnZeAvJWW5ewYOBGx
N/g/KHgdYZ+uhHH/PbGtWktcv5bRJ9Dxbjxsy7l8SLQ6fd/MF/3z6sBJzIHkcDup
DOFdPN/Z0KOw7BOPHAbgghLJTmiESA1Ljxb8848bENlCz8pVizIu2Ilr4xBPtA5o
UfO0FJKbT1T66JZoqwy/drfrlHA7F6c8kYlAmwiOfWHzlWCkE1YuZPJrZQrt4tJ7
0rrPxV1qEGJDumzgcEbU/aYYiBsCAwEAAaOBoTCBnjAdBgNVHSUEFjAUBggrBgEF
BQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUIEr9ryJ0aJuD
CwBsCp7Eun8Hx4AwHwYDVR0jBBgwFoAUmiamd/N/8knrCb1QlhwB4WXCqaswLwYD
VR0RBCgwJoIPbm90LWV4YW1wbGUuY29tghN3d3cubm90LWV4YW1wbGUuY29tMA0G
CSqGSIb3DQEBCwUAA4ICAQBpGLrCt38Z+knbuE1ALEB3hqUQCAm1OPDW6HR+v2nO
f2ERxTwL9Cad++3vONxgB68+6KQeIf5ph48OGnS5DgO13mb2cxLlmM2IJpkbSFtW
VeRNFt/WxRJafpbKw2hgQNJ/sxEAsCyA+kVeh1oCxGQyPO7IIXtw5FecWfIiNNwM
mVM17uchtvsM5BRePvet9xZxrKOFnn6TQRs8vC4e59Y8h52On+L2Q/ytAa7j3+fb
7OYCe+yWypGeosekamZTMBjHFV3RRxsGdRATSuZkv1uewyUnEPmsy5Ow4doSYZKW
QmKjti+vv1YhAhFxPArob0SG3YOiFuKzZ9rSOhUtzSg01ml/kRyOiC7rfO7NRzHq
idhPUhu2QBmdJTLLOBQLvKDNDOHqDYwKdIHJ7pup2y0Fvm4T96q5bnrSdmz/QAlB
XVw08HWMcjeOeHYiHST3yxYfQivTNm2PlKfUACb7vcrQ6pYhOnVdYgJZm6gkV4Xd
K1HKja36snIevv/gSgsE7bGcBYLVCvf16o3IRt9K8CpDoSsWn0iAVcwUP2CyPLm4
QsqA1afjTUPKQTAgDKRecDPhrT1+FjtBwdpXetpRiBK0UE5exfnI4nszZ9+BYG1l
xGUhoOJp0T++nz6R3TX7Rwk7KmG6xX3vWr/MFu5A3c8fvkqj987Vti5BeBezCXfs
rA==
-----END CERTIFICATE-----
`)
