package ra

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	ctasn1 "github.com/google/certificate-transparency-go/asn1"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctpkix "github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/jmhodges/clock"
	akamaipb "github.com/letsencrypt/boulder/akamai/proto"
	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/ctpolicy"
	"github.com/letsencrypt/boulder/ctpolicy/ctconfig"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/identifier"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/policy"
	pubpb "github.com/letsencrypt/boulder/publisher/proto"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/ratelimit"
	"github.com/letsencrypt/boulder/sa"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
	vapb "github.com/letsencrypt/boulder/va/proto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/grpc"
	jose "gopkg.in/square/go-jose.v2"
)

func createPendingAuthorization(t *testing.T, sa core.StorageAuthority, domain string, exp time.Time) int64 {
	t.Helper()

	authz := core.Authorization{
		Identifier:     identifier.DNSIdentifier(domain),
		RegistrationID: 1,
		Status:         "pending",
		Expires:        &exp,
		Challenges: []core.Challenge{
			{
				Token:  core.NewToken(),
				Type:   core.ChallengeTypeHTTP01,
				Status: core.StatusPending,
			},
		},
	}
	authzPB, err := bgrpc.AuthzToPB(authz)
	test.AssertNotError(t, err, "AuthzToPB failed")
	ids, err := sa.NewAuthorizations2(context.Background(), &sapb.AddPendingAuthorizationsRequest{
		Authz: []*corepb.Authorization{authzPB},
	})
	test.AssertNotError(t, err, "sa.NewAuthorizations2 failed")
	return ids.Ids[0]
}

func createFinalizedAuthorization(t *testing.T, sa core.StorageAuthority, domain string, exp time.Time, status string) int64 {
	t.Helper()
	pendingID := createPendingAuthorization(t, sa, domain, exp)
	err := sa.FinalizeAuthorization2(context.Background(), &sapb.FinalizeAuthorizationRequest{
		Id:        pendingID,
		Status:    status,
		Expires:   exp.UnixNano(),
		Attempted: string(core.ChallengeTypeHTTP01),
	})
	test.AssertNotError(t, err, "sa.FinalizeAuthorizations2 failed")
	return pendingID
}

func getAuthorization(t *testing.T, id string, sa core.StorageAuthority) core.Authorization {
	t.Helper()
	var dbAuthz core.Authorization
	idInt, err := strconv.ParseInt(id, 10, 64)
	test.AssertNotError(t, err, "strconv.ParseInt failed")
	dbAuthzPB, err := sa.GetAuthorization2(ctx, &sapb.AuthorizationID2{Id: idInt})
	test.AssertNotError(t, err, "Could not fetch authorization from database")
	dbAuthz, err = bgrpc.PBToAuthz(dbAuthzPB)
	test.AssertNotError(t, err, "bgrpc.PBToAuthz failed")
	return dbAuthz
}

func challTypeIndex(t *testing.T, challenges []core.Challenge, typ core.AcmeChallenge) int64 {
	t.Helper()
	var challIdx int64
	var set bool
	for i, ch := range challenges {
		if ch.Type == typ {
			challIdx = int64(i)
			set = true
			break
		}
	}
	if !set {
		t.Errorf("challTypeIndex didn't find challenge of type: %s", typ)
	}
	return challIdx
}

func numAuthorizations(o *corepb.Order) int {
	return len(o.V2Authorizations)
}

type DummyValidationAuthority struct {
	request      chan *vapb.PerformValidationRequest
	ResultError  error
	ResultReturn *vapb.ValidationResult
}

func (dva *DummyValidationAuthority) PerformValidation(ctx context.Context, req *vapb.PerformValidationRequest, _ ...grpc.CallOption) (*vapb.ValidationResult, error) {
	dva.request <- req
	return dva.ResultReturn, dva.ResultError
}

var (
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
		Identifier: identifier.ACMEIdentifier{
			Type:  identifier.DNS,
			Value: "not-example.com",
		},
	}

	ResponseIndex = 0

	ExampleCSR = &x509.CertificateRequest{}

	Registration = core.Registration{ID: 1}

	log = blog.UseMock()
)

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
	NewOrdersPerAccountPolicy             ratelimit.RateLimitPolicy
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

func (r *dummyRateLimitConfig) NewOrdersPerAccount() ratelimit.RateLimitPolicy {
	return r.NewOrdersPerAccountPolicy
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
	ssa, err := sa.NewSQLStorageAuthority(dbMap, fc, log, metrics.NoopRegisterer, 1)
	if err != nil {
		t.Fatalf("Failed to create SA: %s", err)
	}

	saDBCleanUp := test.ResetSATestDatabase(t)

	va := &DummyValidationAuthority{request: make(chan *vapb.PerformValidationRequest, 1)}

	pa, err := policy.New(map[core.AcmeChallenge]bool{
		core.ChallengeTypeHTTP01: true,
		core.ChallengeTypeDNS01:  true,
	})
	test.AssertNotError(t, err, "Couldn't create PA")
	err = pa.SetHostnamePolicyFile("../test/hostname-policy.yaml")
	test.AssertNotError(t, err, "Couldn't set hostname policy")

	stats := metrics.NoopRegisterer

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

	ctp := ctpolicy.New(&mocks.Publisher{}, nil, nil, log, metrics.NoopRegisterer)

	ra := NewRegistrationAuthorityImpl(fc,
		log,
		stats,
		1, testKeyPolicy, 100, true, 300*24*time.Hour, 7*24*time.Hour, nil, noopCAA{}, 0, ctp, nil, nil)
	ra.SA = ssa
	ra.VA = va
	ra.CA = ca
	ra.PA = pa
	ra.reuseValidAuthz = true

	return va, ssa, ra, fc, cleanUp
}

func assertAuthzEqual(t *testing.T, a1, a2 core.Authorization) {
	t.Helper()
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
	unparsable := "mailto:a@email.com, b@email.com"
	forbidden := "mailto:a@example.org"

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

	err = ra.validateContacts(context.Background(), &[]string{unparsable})
	test.AssertError(t, err, "Unparsable email")

	err = ra.validateContacts(context.Background(), &[]string{forbidden})
	test.AssertError(t, err, "Forbidden email")

	err = ra.validateContacts(context.Background(), &[]string{"mailto:admin@localhost"})
	test.AssertError(t, err, "Forbidden email")

	err = ra.validateContacts(context.Background(), &[]string{"mailto:admin@example.not.a.iana.suffix"})
	test.AssertError(t, err, "Forbidden email")

	err = ra.validateContacts(context.Background(), &[]string{"mailto:admin@1.2.3.4"})
	test.AssertError(t, err, "Forbidden email")

	err = ra.validateContacts(context.Background(), &[]string{"mailto:admin@[1.2.3.4]"})
	test.AssertError(t, err, "Forbidden email")

	err = ra.validateContacts(context.Background(), &[]string{"mailto:admin@a.com?no-reminder-emails"})
	test.AssertError(t, err, "No hfields in email")

	// The registrations.contact field is VARCHAR(191). 175 'a' characters plus
	// the prefix "mailto:" and the suffix "@a.com" makes exactly 191 bytes of
	// encoded JSON. The correct size to hit our maximum DB field length.
	var longStringBuf strings.Builder
	longStringBuf.WriteString("mailto:")
	for i := 0; i < 175; i++ {
		longStringBuf.WriteRune('a')
	}
	longStringBuf.WriteString("@a.com")

	err = ra.validateContacts(context.Background(), &[]string{longStringBuf.String()})
	test.AssertError(t, err, "Too long contacts")
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

	authz, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization failed")

	// Verify that returned authz same as DB
	dbAuthz := getAuthorization(t, authz.ID, sa)
	assertAuthzEqual(t, authz, dbAuthz)

	// Verify that the returned authz has the right information
	test.Assert(t, authz.RegistrationID == Registration.ID, "Initial authz did not get the right registration ID")
	test.Assert(t, authz.Identifier == AuthzRequest.Identifier, "Initial authz had wrong identifier")
	test.Assert(t, authz.Status == core.StatusPending, "Initial authz not pending")

	// TODO Verify that challenges are correct
	test.Assert(t, len(authz.Challenges) == 2, "Incorrect number of challenges returned")
	for _, c := range authz.Challenges {
		if c.Type != core.ChallengeTypeHTTP01 && c.Type != core.ChallengeTypeDNS01 {
			t.Errorf("unsupported challenge type %s", c.Type)
		}
		test.AssertNotError(t, c.CheckConsistencyForClientOffer(), "CheckConsistencyForClientOffer for Challenge 0 returned an error")
	}
}

func TestReuseValidAuthorization(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Turn on AuthZ Reuse
	ra.reuseValidAuthz = true

	// Create one finalized authorization
	exp := ra.clk.Now().Add(365 * 24 * time.Hour)
	authzIDA := createFinalizedAuthorization(t, sa, "not-example.com", exp, "valid")

	// Now create another authorization for the same Reg.ID/domain
	secondAuthz, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization for secondAuthz failed")

	// The first authz should be reused as the second and thus have the same ID
	test.AssertEquals(t, fmt.Sprintf("%d", authzIDA), secondAuthz.ID)

	// The second authz shouldn't be pending, it should be valid (that's why it
	// was reused)
	test.AssertEquals(t, secondAuthz.Status, core.StatusValid)

	// It should have one http challenge already marked valid
	httpIndex := ResponseIndex
	httpChallenge := secondAuthz.Challenges[httpIndex]
	test.AssertEquals(t, httpChallenge.Type, core.ChallengeTypeHTTP01)
	test.AssertEquals(t, httpChallenge.Status, core.StatusValid)

	// Sending an update to this authz for an already valid challenge should do
	// nothing (but produce no error), since it is already a valid authz
	authzPB, err := bgrpc.AuthzToPB(secondAuthz)
	test.AssertNotError(t, err, "Failed to serialize secondAuthz")
	authzPB, err = ra.PerformValidation(ctx, &rapb.PerformValidationRequest{
		Authz:          authzPB,
		ChallengeIndex: int64(httpIndex)})
	test.AssertNotError(t, err, "PerformValidation on secondAuthz http failed")
	secondAuthz, err = bgrpc.PBToAuthz(authzPB)
	test.AssertNotError(t, err, "Failed to deserialize PerformValidation result for secondAuthz")
	test.AssertEquals(t, fmt.Sprintf("%d", authzIDA), secondAuthz.ID)
	test.AssertEquals(t, secondAuthz.Status, core.StatusValid)

	authzPB, err = ra.PerformValidation(ctx, &rapb.PerformValidationRequest{
		Authz:          authzPB,
		ChallengeIndex: int64(httpIndex)})
	test.AssertNotError(t, err, "PerformValidation on secondAuthz sni failed")
	secondAuthz, err = bgrpc.PBToAuthz(authzPB)
	test.AssertNotError(t, err, "Failed to deserialize PerformValidation result for secondAuthz")
	test.AssertEquals(t, fmt.Sprintf("%d", authzIDA), secondAuthz.ID)
	test.AssertEquals(t, secondAuthz.Status, core.StatusValid)
}

func TestReusePendingAuthorization(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Create one pending authorization
	firstAuthz, err := ra.NewAuthorization(ctx, core.Authorization{
		Identifier:     identifier.DNSIdentifier("not-example.com"),
		RegistrationID: 1,
		Status:         "pending",
	}, Registration.ID)
	test.AssertNotError(t, err, "Could not store test pending authorization")

	// Create another one with the same identifier
	secondAuthz, err := ra.NewAuthorization(ctx, core.Authorization{
		Identifier: identifier.DNSIdentifier("not-example.com"),
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
		Identifier: identifier.DNSIdentifier("not-example.com"),
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

func (m mockSAWithBadGetValidAuthz) GetValidAuthorizations2(
	ctx context.Context,
	_ *sapb.GetValidAuthorizationsRequest) (*sapb.Authorizations, error) {
	return nil, fmt.Errorf("mockSAWithBadGetValidAuthz always errors!")
}

func TestReuseAuthorizationFaultySA(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Turn on AuthZ Reuse
	ra.reuseValidAuthz = true

	// Use a mock SA that always fails `GetValidAuthorizations` and
	// `GetValidAuthorizations2`
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
	ra.reuseValidAuthz = false

	// Create one finalized authorization
	exp := ra.clk.Now().Add(365 * 24 * time.Hour)
	authzID := createFinalizedAuthorization(t, sa, "not-example.com", exp, "valid")

	// Now create another authorization for the same Reg.ID/domain
	secondAuthz, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization for secondAuthz failed")

	// The second authz should not have the same ID as the previous AuthZ,
	// because we have set `reuseValidAuthZ` to false. It should be a fresh
	// & unique authz
	test.AssertNotEquals(t, fmt.Sprintf("%d", authzID), secondAuthz.ID)

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
	exp := ra.clk.Now().Add(12 * time.Hour)
	authzID := createFinalizedAuthorization(t, sa, "not-example", exp, "valid")

	// Now create another authorization for the same Reg.ID/domain
	secondAuthz, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization for secondAuthz failed")

	// The second authz should not have the same ID as the previous AuthZ,
	// because the existing valid authorization expires within 1 day from now
	test.AssertNotEquals(t, fmt.Sprintf("%d", authzID), secondAuthz.ID)

	// The second authz shouldn't be valid, but pending since it is a brand new
	// authz, not a reused one
	test.AssertEquals(t, secondAuthz.Status, core.StatusPending)
}

func TestNewAuthorizationCapitalLetters(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	authzReq := core.Authorization{
		Identifier: identifier.ACMEIdentifier{
			Type:  identifier.DNS,
			Value: "NOT-example.COM",
		},
	}
	authz, err := ra.NewAuthorization(ctx, authzReq, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization failed")
	test.AssertEquals(t, "not-example.com", authz.Identifier.Value)

	dbAuthz := getAuthorization(t, authz.ID, sa)
	assertAuthzEqual(t, authz, dbAuthz)
}

func TestNewAuthorizationInvalidName(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	authzReq := core.Authorization{
		Identifier: identifier.ACMEIdentifier{
			Type:  identifier.DNS,
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

func TestPerformValidationExpired(t *testing.T) {
	_, _, ra, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	authz, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization failed")

	expiry := fc.Now().Add(-2 * time.Hour)
	authz.Expires = &expiry

	authzPB, err := bgrpc.AuthzToPB(authz)
	test.AssertNotError(t, err, "AuthzToPB failed")

	_, err = ra.PerformValidation(ctx, &rapb.PerformValidationRequest{
		Authz:          authzPB,
		ChallengeIndex: int64(ResponseIndex),
	})
	test.AssertError(t, err, "Updated expired authorization")
}

func TestPerformValidationAlreadyValid(t *testing.T) {
	va, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.reuseValidAuthz = false

	// Create a finalized authorization
	exp := ra.clk.Now().Add(365 * 24 * time.Hour)
	authz := core.Authorization{
		Identifier:     identifier.DNSIdentifier("not-example.com"),
		RegistrationID: 1,
		Status:         "valid",
		Expires:        &exp,
		Challenges: []core.Challenge{
			{
				Token:  core.NewToken(),
				Type:   core.ChallengeTypeHTTP01,
				Status: core.StatusPending,
			},
		},
	}
	authzPB, err := bgrpc.AuthzToPB(authz)
	test.AssertNotError(t, err, "bgrpc.AuthzToPB failed")

	fakeHostname := "example.com"
	fakePort := "8080"
	va.ResultReturn = &vapb.ValidationResult{
		Records: []*corepb.ValidationRecord{
			{
				AddressUsed: []byte("192.168.0.1"),
				Hostname:    &fakeHostname,
				Port:        &fakePort,
				Url:         &fakeHostname,
			},
		},
		Problems: nil,
	}

	// A subsequent call to perform validation should return the expected error
	_, err = ra.PerformValidation(ctx, &rapb.PerformValidationRequest{
		Authz:          authzPB,
		ChallengeIndex: int64(ResponseIndex),
	})
	test.Assert(t, berrors.Is(err, berrors.WrongAuthorizationState),
		"PerformValidation of valid authz (with reuseValidAuthz disabled) didn't return a berrors.WrongAuthorizationState")
}

func TestPerformValidationSuccess(t *testing.T) {
	va, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// We know this is OK because of TestNewAuthorization
	authz, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization failed")

	challIdx := challTypeIndex(t, authz.Challenges, core.ChallengeTypeDNS01)

	fakeHostname := "example.com"
	fakePort := "8080"
	va.ResultReturn = &vapb.ValidationResult{
		Records: []*corepb.ValidationRecord{
			{
				AddressUsed: []byte("192.168.0.1"),
				Hostname:    &fakeHostname,
				Port:        &fakePort,
				Url:         &fakeHostname,
			},
		},
		Problems: nil,
	}

	authzPB, err := bgrpc.AuthzToPB(authz)
	test.AssertNotError(t, err, "AuthzToPB failed")

	authzPB, err = ra.PerformValidation(ctx, &rapb.PerformValidationRequest{
		Authz:          authzPB,
		ChallengeIndex: challIdx,
	})
	test.AssertNotError(t, err, "PerformValidation failed")
	authz, err = bgrpc.PBToAuthz(authzPB)
	test.AssertNotError(t, err, "PBToAuthz failed")

	var vaRequest *vapb.PerformValidationRequest
	select {
	case r := <-va.request:
		vaRequest = r
	case <-time.After(time.Second):
		t.Fatal("Timed out waiting for DummyValidationAuthority.PerformValidation to complete")
	}

	// Verify that the VA got the request, and it's the same as the others
	test.AssertEquals(t, string(authz.Challenges[challIdx].Type), *vaRequest.Challenge.Type)
	test.AssertEquals(t, authz.Challenges[challIdx].Token, *vaRequest.Challenge.Token)

	// Sleep so the RA has a chance to write to the SA
	time.Sleep(100 * time.Millisecond)

	dbAuthz := getAuthorization(t, authz.ID, sa)
	t.Log("dbAuthz:", dbAuthz)

	// Verify that the responses are reflected
	test.AssertNotNil(t, vaRequest.Challenge, "Request passed to VA has no challenge")
	challIdx = challTypeIndex(t, dbAuthz.Challenges, core.ChallengeTypeDNS01)
	fmt.Println(dbAuthz.Challenges[challIdx])
	test.Assert(t, dbAuthz.Challenges[challIdx].Status == core.StatusValid, "challenge was not marked as valid")

	// The DB authz's expiry should be equal to the current time plus the
	// configured authorization lifetime
	expectedExpires := ra.clk.Now().Add(ra.authorizationLifetime)
	test.AssertEquals(t, *dbAuthz.Expires, expectedExpires)
}

func TestPerformValidationVAError(t *testing.T) {
	va, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	authz, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization failed")

	challIdx := challTypeIndex(t, authz.Challenges, core.ChallengeTypeDNS01)

	va.ResultError = fmt.Errorf("Something went wrong")

	authzPB, err := bgrpc.AuthzToPB(authz)
	test.AssertNotError(t, err, "AuthzToPB failed")

	authzPB, err = ra.PerformValidation(ctx, &rapb.PerformValidationRequest{
		Authz:          authzPB,
		ChallengeIndex: challIdx,
	})

	test.AssertNotError(t, err, "PerformValidation completely failed")
	authz, err = bgrpc.PBToAuthz(authzPB)
	test.AssertNotError(t, err, "PBToAuthz failed")

	var vaRequest *vapb.PerformValidationRequest
	select {
	case r := <-va.request:
		vaRequest = r
	case <-time.After(time.Second):
		t.Fatal("Timed out waiting for DummyValidationAuthority.PerformValidation to complete")
	}

	// Verify that the VA got the request, and it's the same as the others
	test.AssertEquals(t, string(authz.Challenges[challIdx].Type), *vaRequest.Challenge.Type)
	test.AssertEquals(t, authz.Challenges[challIdx].Token, *vaRequest.Challenge.Token)

	// Sleep so the RA has a chance to write to the SA
	time.Sleep(100 * time.Millisecond)

	dbAuthz := getAuthorization(t, authz.ID, sa)
	t.Log("dbAuthz:", dbAuthz)

	// Verify that the responses are reflected
	challIdx = challTypeIndex(t, dbAuthz.Challenges, core.ChallengeTypeDNS01)
	test.Assert(t, dbAuthz.Challenges[challIdx].Status == core.StatusInvalid, "challenge was not marked as invalid")
	test.AssertContains(t, dbAuthz.Challenges[challIdx].Error.Error(), "Could not communicate with VA")
	test.Assert(t, dbAuthz.Challenges[challIdx].ValidationRecord == nil, "challenge had a ValidationRecord")
}

func TestCertificateKeyNotEqualAccountKey(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	exp := ra.clk.Now().Add(365 * 24 * time.Hour)
	_ = createFinalizedAuthorization(t, sa, "www.example.com", exp, "valid")
	csr := x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKey:          AccountKeyA.Key,
		DNSNames:           []string{"www.example.com"},
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csr, AccountPrivateKey.Key)
	test.AssertNotError(t, err, "Failed to sign CSR")
	parsedCSR, err := x509.ParseCertificateRequest(csrBytes)
	test.AssertNotError(t, err, "Failed to parse CSR")
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
	exp := ra.clk.Now().Add(365 * 24 * time.Hour)
	_ = createFinalizedAuthorization(t, sa, "not-example.com", exp, "valid")

	// ExampleCSR requests not-example.com and www.not-example.com,
	// but the authorization only covers not-example.com
	certRequest := core.CertificateRequest{
		CSR: ExampleCSR,
	}

	_, err := ra.NewCertificate(ctx, certRequest, 1)
	test.Assert(t, err != nil, "Issued certificate with insufficient authorization")
}

func TestNewCertificate(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	exp := ra.clk.Now().Add(365 * 24 * time.Hour)
	// Create valid authorizations for not-example.com and www.not-example.com
	_ = createFinalizedAuthorization(t, sa, "not-example.com", exp, "valid")
	_ = createFinalizedAuthorization(t, sa, "www.not-example.com", exp, "valid")

	// Check that we fail if the CSR signature is invalid
	ExampleCSR.Signature[0]++
	certRequest := core.CertificateRequest{
		CSR: ExampleCSR,
	}

	_, err := ra.NewCertificate(ctx, certRequest, Registration.ID)
	ExampleCSR.Signature[0]--
	test.AssertError(t, err, "Failed to check CSR signature")

	// Check that we don't fail on case mismatches
	ExampleCSR.Subject.CommonName = "www.NOT-example.com"
	certRequest = core.CertificateRequest{
		CSR: ExampleCSR,
	}

	cert, err := ra.NewCertificate(ctx, certRequest, Registration.ID)
	test.AssertNotError(t, err, "Failed to issue certificate")

	_, err = x509.ParseCertificate(cert.DER)
	test.AssertNotError(t, err, "Failed to parse certificate")
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
	authz.Challenges[0].Status = core.StatusInvalid
	err = ra.recordValidation(ctx, authz.ID, authz.Expires, &authz.Challenges[0])
	test.AssertNotError(t, err, "recordValidation failed")

	// Try to create a new authzRequest, should be fine now.
	_, err = ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization failed")
}

func TestNewOrderRateLimiting(t *testing.T) {
	_, _, ra, fc, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.orderLifetime = 5 * 24 * time.Hour

	rateLimitDuration := 5 * time.Minute

	// Create a dummy rate limit config that sets a NewOrdersPerAccount rate
	// limit with a very low threshold/short window
	ra.rlPolicies = &dummyRateLimitConfig{
		NewOrdersPerAccountPolicy: ratelimit.RateLimitPolicy{
			Threshold: 1,
			Window:    cmd.ConfigDuration{Duration: rateLimitDuration},
		},
	}

	orderOne := &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
		Names:          []string{"first.example.com"},
	}
	orderTwo := &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
		Names:          []string{"second.example.com"},
	}

	// To start, it should be possible to create a new order
	_, err := ra.NewOrder(ctx, orderOne)
	test.AssertNotError(t, err, "NewOrder for orderOne failed")

	// Advance the clock 1s to separate the orders in time
	fc.Add(time.Second)

	// Creating an order immediately after the first with different names
	// should fail
	_, err = ra.NewOrder(ctx, orderTwo)
	test.AssertError(t, err, "NewOrder for orderTwo succeeded, should have been ratelimited")

	// Creating the first order again should succeed because of order reuse, no
	// new pending order is produced.
	_, err = ra.NewOrder(ctx, orderOne)
	test.AssertNotError(t, err, "Reuse of orderOne failed")

	// Advancing the clock by 2 * the rate limit duration should allow orderTwo to
	// succeed
	fc.Add(2 * rateLimitDuration)
	_, err = ra.NewOrder(ctx, orderTwo)
	test.AssertNotError(t, err, "NewOrder for orderTwo failed after advancing clock")
}

// TestEarlyOrderRateLimiting tests that NewOrder applies the certificates per
// name/per FQDN rate limits against the order names.
func TestEarlyOrderRateLimiting(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.orderLifetime = 5 * 24 * time.Hour

	rateLimitDuration := 5 * time.Minute

	domain := "early-ratelimit-example.com"

	// Set a mock RL policy with a CertificatesPerName threshold for the domain
	// name so low if it were enforced it would prevent a new order for any names.
	ra.rlPolicies = &dummyRateLimitConfig{
		CertificatesPerNamePolicy: ratelimit.RateLimitPolicy{
			Threshold: 10,
			Window:    cmd.ConfigDuration{Duration: rateLimitDuration},
			// Setting the Threshold to 0 skips applying the rate limit. Setting an
			// override to 0 does the trick.
			Overrides: map[string]int{
				domain: 0,
			},
		},
		NewOrdersPerAccountPolicy: ratelimit.RateLimitPolicy{
			Threshold: 10,
			Window:    cmd.ConfigDuration{Duration: rateLimitDuration},
		},
	}

	// Request an order for the test domain
	newOrder := &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
		Names:          []string{domain},
	}

	// With the feature flag enabled the NewOrder request should fail because of
	// the CertificatesPerNamePolicy.
	_, err := ra.NewOrder(ctx, newOrder)
	test.AssertError(t, err, "NewOrder did not apply cert rate limits with feature flag enabled")

	// The err should be the expected rate limit error
	expectedErrPrefix := "too many certificates already issued for: " +
		"early-ratelimit-example.com"
	test.Assert(t,
		strings.HasPrefix(err.Error(), expectedErrPrefix),
		fmt.Sprintf("expected error to have prefix %q got %q", expectedErrPrefix, err))
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
	ra.SA = &mockInvalidAuthorizationsAuthority{domainWithFailures: "ifail.com"}
	// Should trigger rate limit
	_, err := ra.NewAuthorization(ctx, core.Authorization{
		Identifier: identifier.DNSIdentifier("ifail.com"),
	}, Registration.ID)
	test.AssertError(t, err, "NewAuthorization did not encounter expected rate limit error")
	test.AssertEquals(t, err.Error(), "too many failed authorizations recently: see https://letsencrypt.org/docs/rate-limits/")
}

func TestAuthzFailedRateLimitingNewOrder(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	ra.rlPolicies = &dummyRateLimitConfig{
		InvalidAuthorizationsPerAccountPolicy: ratelimit.RateLimitPolicy{
			Threshold: 1,
			Window:    cmd.ConfigDuration{Duration: 1 * time.Hour},
		},
	}

	testcase := func() {
		ra.SA = &mockInvalidAuthorizationsAuthority{domainWithFailures: "all.i.do.is.lose.com"}
		err := ra.checkInvalidAuthorizationLimits(ctx, Registration.ID,
			[]string{"charlie.brown.com", "all.i.do.is.lose.com"})
		test.AssertError(t, err, "checkInvalidAuthorizationLimits did not encounter expected rate limit error")
		test.AssertEquals(t, err.Error(), "too many failed authorizations recently: see https://letsencrypt.org/docs/rate-limits/")
	}

	testcase()
}

func TestDomainsForRateLimiting(t *testing.T) {
	domains, err := domainsForRateLimiting([]string{})
	test.AssertNotError(t, err, "failed on empty")
	test.AssertEquals(t, len(domains), 0)

	domains, err = domainsForRateLimiting([]string{"www.example.com", "example.com"})
	test.AssertNotError(t, err, "failed on example.com")
	test.AssertDeepEquals(t, domains, []string{"example.com"})

	domains, err = domainsForRateLimiting([]string{"www.example.com", "example.com", "www.example.co.uk"})
	test.AssertNotError(t, err, "failed on example.co.uk")
	test.AssertDeepEquals(t, domains, []string{"example.co.uk", "example.com"})

	domains, err = domainsForRateLimiting([]string{"www.example.com", "example.com", "www.example.co.uk", "co.uk"})
	test.AssertNotError(t, err, "should not fail on public suffix")
	test.AssertDeepEquals(t, domains, []string{"co.uk", "example.co.uk", "example.com"})

	domains, err = domainsForRateLimiting([]string{"foo.bar.baz.www.example.com", "baz.example.com"})
	test.AssertNotError(t, err, "failed on foo.bar.baz")
	test.AssertDeepEquals(t, domains, []string{"example.com"})

	domains, err = domainsForRateLimiting([]string{"github.io", "foo.github.io", "bar.github.io"})
	test.AssertNotError(t, err, "failed on public suffix private domain")
	test.AssertDeepEquals(t, domains, []string{"bar.github.io", "foo.github.io", "github.io"})
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
	test.AssertEquals(t, ra.rlPolicies.CertificatesPerName().Overrides["le.wtf"], 10000)
	test.AssertEquals(t, ra.rlPolicies.RegistrationsPerIP().Overrides["127.0.0.1"], 1000000)
	test.AssertEquals(t, ra.rlPolicies.PendingAuthorizationsPerAccount().Threshold, 150)
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
	test.AssertEquals(t, ra.rlPolicies.CertificatesPerName().Overrides["le.wtf"], 9999)
	test.AssertEquals(t, ra.rlPolicies.CertificatesPerName().Overrides["le4.wtf"], 9999)
	test.AssertEquals(t, ra.rlPolicies.RegistrationsPerIP().Overrides["127.0.0.1"], 999990)
	test.AssertEquals(t, ra.rlPolicies.PendingAuthorizationsPerAccount().Threshold, 999)
	test.AssertEquals(t, ra.rlPolicies.CertificatesPerFQDNSet().Overrides["le.wtf"], 9999)
	test.AssertEquals(t, ra.rlPolicies.CertificatesPerFQDNSet().Threshold, 99999)
}

type mockSAWithNameCounts struct {
	mocks.StorageAuthority
	nameCounts map[string]*sapb.CountByNames_MapElement
	t          *testing.T
	clk        clock.FakeClock
}

func (m mockSAWithNameCounts) CountCertificatesByNames(ctx context.Context, names []string, earliest, latest time.Time) (ret []*sapb.CountByNames_MapElement, err error) {
	if latest != m.clk.Now() {
		m.t.Errorf("incorrect latest: was %s, expected %s", latest, m.clk.Now())
	}
	expectedEarliest := m.clk.Now().Add(-23 * time.Hour)
	if earliest != expectedEarliest {
		m.t.Errorf("incorrect earliest: was %s, expected %s", earliest, expectedEarliest)
	}
	var results []*sapb.CountByNames_MapElement
	for _, name := range names {
		if entry, ok := m.nameCounts[name]; ok {
			results = append(results, entry)
		}
	}
	return results, nil
}

func nameCount(domain string, count int) *sapb.CountByNames_MapElement {
	pbInt := int64(count)
	return &sapb.CountByNames_MapElement{
		Name:  domain,
		Count: pbInt,
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

	// Two base domains, one above threshold, one below
	mockSA.nameCounts["example.com"] = nameCount("example.com", 10)
	mockSA.nameCounts["good-example.com"] = nameCount("good-example.com", 1)
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"www.example.com", "example.com", "good-example.com"}, rlp, 99)
	test.AssertError(t, err, "incorrectly failed to rate limit example.com")
	if !berrors.Is(err, berrors.RateLimit) {
		t.Errorf("Incorrect error type %#v", err)
	}
	// Verify it has no sub errors as there is only one bad name
	test.AssertEquals(t, err.Error(), "too many certificates already issued for: example.com: see https://letsencrypt.org/docs/rate-limits/")
	test.AssertEquals(t, len(err.(*berrors.BoulderError).SubErrors), 0)

	// Three base domains, two above threshold, one below
	mockSA.nameCounts["example.com"] = nameCount("example.com", 10)
	mockSA.nameCounts["other-example.com"] = nameCount("other-example.com", 10)
	mockSA.nameCounts["good-example.com"] = nameCount("good-example.com", 1)
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"example.com", "other-example.com", "good-example.com"}, rlp, 99)
	test.AssertError(t, err, "incorrectly failed to rate limit example.com, other-example.com")
	if !berrors.Is(err, berrors.RateLimit) {
		t.Errorf("Incorrect error type %#v", err)
	}
	// Verify it has two sub errors as there are two bad names
	test.AssertEquals(t, err.Error(), "too many certificates already issued for multiple names (example.com and 2 others): see https://letsencrypt.org/docs/rate-limits/")
	test.AssertEquals(t, len(err.(*berrors.BoulderError).SubErrors), 2)

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
			count += entry.Count
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
			"test.dedyn.io":  nameCount("test.dedyn.io", 1),
			"test2.dedyn.io": nameCount("test2.dedyn.io", 1),
			"test3.dedyn.io": nameCount("test3.dedyn.io", 0),
			"dedyn.io":       nameCount("dedyn.io", 0),
			"dynv6.net":      nameCount("dynv6.net", 2),
		},
		clk: fc,
		t:   t,
	}
	ra.SA = mockSA

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

func TestDeactivateAuthorization(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	exp := ra.clk.Now().Add(365 * 24 * time.Hour)
	authzID := createFinalizedAuthorization(t, sa, "not-example.com", exp, "valid")
	authz := getAuthorization(t, fmt.Sprintf("%d", authzID), sa)
	err := ra.DeactivateAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Could not deactivate authorization")
	deact, err := sa.GetAuthorization2(ctx, &sapb.AuthorizationID2{Id: authzID})
	test.AssertNotError(t, err, "Could not get deactivated authorization with ID "+authz.ID)
	test.AssertEquals(t, *deact.Status, string(core.StatusDeactivated))
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
	in *vapb.IsCAAValidRequest,
	opts ...grpc.CallOption,
) (*vapb.IsCAAValidResponse, error) {
	return &vapb.IsCAAValidResponse{}, nil
}

// caaRecorder implements caaChecker, always returning nil, but recording the
// names it was called for.
type caaRecorder struct {
	sync.Mutex
	names map[string]bool
}

func (cr *caaRecorder) IsCAAValid(
	ctx context.Context,
	in *vapb.IsCAAValidRequest,
	opts ...grpc.CallOption,
) (*vapb.IsCAAValidResponse, error) {
	cr.Lock()
	defer cr.Unlock()
	cr.names[in.Domain] = true
	return &vapb.IsCAAValidResponse{}, nil
}

// A mock SA that returns special authzs for testing rechecking of CAA (in
// TestRecheckCAADates below)
type mockSAWithRecentAndOlder struct {
	authzMap map[string]*core.Authorization
	mocks.StorageAuthority
}

func newMockSAWithRecentAndOlder(recent, older time.Time) *mockSAWithRecentAndOlder {
	makeIdentifier := func(name string) identifier.ACMEIdentifier {
		return identifier.ACMEIdentifier{
			Type:  identifier.DNS,
			Value: name,
		}
	}
	basicChallenge := core.Challenge{Status: core.StatusValid, Type: core.ChallengeTypeHTTP01, Token: "exampleToken"}
	return &mockSAWithRecentAndOlder{
		authzMap: map[string]*core.Authorization{
			"recent.com": {
				Identifier: makeIdentifier("recent.com"),
				Expires:    &recent,
				Challenges: []core.Challenge{basicChallenge},
			},
			"older.com": {
				Identifier: makeIdentifier("older.com"),
				Expires:    &older,
				Challenges: []core.Challenge{basicChallenge},
			},
			"older2.com": {
				Identifier: makeIdentifier("older2.com"),
				Expires:    &older,
				Challenges: []core.Challenge{basicChallenge},
			},
			"wildcard.com": {
				Identifier: makeIdentifier("wildcard.com"),
				Expires:    &older,
				Challenges: []core.Challenge{basicChallenge},
			},
			"*.wildcard.com": {
				Identifier: makeIdentifier("*.wildcard.com"),
				Expires:    &older,
				Challenges: []core.Challenge{basicChallenge},
			},
		},
	}
}

func (m *mockSAWithRecentAndOlder) GetValidAuthorizations(
	ctx context.Context,
	registrationID int64,
	names []string,
	now time.Time) (map[string]*core.Authorization, error) {
	return m.authzMap, nil
}

func (m *mockSAWithRecentAndOlder) GetValidAuthorizations2(_ context.Context, _ *sapb.GetValidAuthorizationsRequest) (*sapb.Authorizations, error) {
	return sa.AuthzMapToPB(m.authzMap)
}

// Test that the right set of domain names have their CAA rechecked, based on
// expiration time.
func TestRecheckCAADates(t *testing.T) {
	_, _, ra, fc, cleanUp := initAuthorities(t)
	defer cleanUp()
	recorder := &caaRecorder{names: make(map[string]bool)}
	ra.caa = recorder
	ra.authorizationLifetime = 15 * time.Hour
	ra.SA = newMockSAWithRecentAndOlder(
		fc.Now().Add(15*time.Hour),
		fc.Now().Add(5*time.Hour),
	)

	// NOTE: The names provided here correspond to authorizations in the
	// `mockSAWithRecentAndOlder`
	names := []string{"recent.com", "older.com", "older2.com", "wildcard.com", "*.wildcard.com"}
	_, err := ra.checkAuthorizations(context.Background(), names, 999)
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
	in *vapb.IsCAAValidRequest,
	opts ...grpc.CallOption,
) (*vapb.IsCAAValidResponse, error) {
	cvrpb := &vapb.IsCAAValidResponse{}
	switch in.Domain {
	case "a.com":
		cvrpb.Problem = &corepb.ProblemDetails{
			Detail: proto.String("CAA invalid for a.com"),
		}
	case "c.com":
		cvrpb.Problem = &corepb.ProblemDetails{
			Detail: proto.String("CAA invalid for c.com"),
		}
	case "d.com":
		return nil, fmt.Errorf("Error checking CAA for d.com")
	}
	return cvrpb, nil
}

func TestRecheckCAAEmpty(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	if err := ra.recheckCAA(context.Background(), nil); err != nil {
		t.Errorf("expected nil err, got %s", err)
	}
}

func makeHTTP01Authorization(domain string) *core.Authorization {
	return &core.Authorization{
		Identifier: identifier.ACMEIdentifier{Type: identifier.DNS, Value: domain},
		Challenges: []core.Challenge{{Status: core.StatusValid, Type: core.ChallengeTypeHTTP01}},
	}
}

func TestRecheckCAASuccess(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	authzs := []*core.Authorization{
		makeHTTP01Authorization("a.com"),
		makeHTTP01Authorization("b.com"),
		makeHTTP01Authorization("c.com"),
	}
	if err := ra.recheckCAA(context.Background(), authzs); err != nil {
		t.Errorf("expected nil err, got %s", err)
	}
}

func TestRecheckCAAFail(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.caa = &caaFailer{}
	authzs := []*core.Authorization{
		makeHTTP01Authorization("a.com"),
		makeHTTP01Authorization("b.com"),
		makeHTTP01Authorization("c.com"),
	}
	err := ra.recheckCAA(context.Background(), authzs)

	if err == nil {
		t.Fatalf("expected err, got nil")
	} else if !berrors.Is(err, berrors.CAA) {
		t.Fatalf("expected CAA error, got %T", err)
	}

	// NOTE(@cpu): Safe to skip the cast check here because we already checked err
	// with `berrors.Is(err, berrors.CAA)`
	berr, _ := err.(*berrors.BoulderError)

	// There should be two sub errors
	test.AssertEquals(t, len(berr.SubErrors), 2)

	// We don't know whether the asynchronous a.com or c.com CAA recheck will fail
	// first. Whichever does will be mentioned in the top level problem detail.
	expectedDetailRegex := regexp.MustCompile(
		`Rechecking CAA for "(?:a\.com|c\.com)" and 1 more identifiers failed. Refer to sub-problems for more information`,
	)
	if !expectedDetailRegex.MatchString(berr.Detail) {
		t.Errorf("expected suberror detail to match expected regex, got %q", err)
	}

	// There should be a sub error for both a.com and c.com with the correct type
	subErrMap := make(map[string]berrors.SubBoulderError, len(berr.SubErrors))
	for _, subErr := range berr.SubErrors {
		subErrMap[subErr.Identifier.Value] = subErr
	}
	subErrA, foundA := subErrMap["a.com"]
	subErrB, foundB := subErrMap["c.com"]
	test.AssertEquals(t, foundA, true)
	test.AssertEquals(t, foundB, true)
	test.AssertEquals(t, subErrA.Type, berrors.CAA)
	test.AssertEquals(t, subErrB.Type, berrors.CAA)

	// Recheck CAA with just one bad authz
	authzs = []*core.Authorization{
		makeHTTP01Authorization("a.com"),
	}
	err = ra.recheckCAA(context.Background(), authzs)
	// It should error
	test.AssertError(t, err, "expected err from recheckCAA")
	// It should be a berror
	berr, ok := err.(*berrors.BoulderError)
	test.AssertEquals(t, ok, true)
	// There should be *no* suberrors because there was only one overall error
	test.AssertEquals(t, len(berr.SubErrors), 0)
}

func TestRecheckCAAInternalServerError(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.caa = &caaFailer{}
	authzs := []*core.Authorization{
		makeHTTP01Authorization("a.com"),
		makeHTTP01Authorization("b.com"),
		makeHTTP01Authorization("d.com"),
	}
	if err := ra.recheckCAA(context.Background(), authzs); err == nil {
		t.Errorf("expected err, got nil")
	} else if !berrors.Is(err, berrors.InternalServer) {
		t.Errorf("expected InternalServer error, got %T", err)
	}
}

func TestNewOrder(t *testing.T) {
	_, _, ra, fc, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.orderLifetime = time.Hour

	orderA, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
		Names:          []string{"b.com", "a.com", "a.com", "C.COM"},
	})
	test.AssertNotError(t, err, "ra.NewOrder failed")
	test.AssertEquals(t, *orderA.RegistrationID, int64(1))
	test.AssertEquals(t, *orderA.Expires, fc.Now().Add(time.Hour).UnixNano())
	test.AssertEquals(t, len(orderA.Names), 3)
	// We expect the order names to have been sorted, deduped, and lowercased
	test.AssertDeepEquals(t, orderA.Names, []string{"a.com", "b.com", "c.com"})
	test.AssertEquals(t, *orderA.Id, int64(1))
	test.AssertEquals(t, numAuthorizations(orderA), 3)

	// Reuse all existing authorizations
	orderB, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
		Names:          []string{"b.com", "a.com", "C.COM"},
	})
	test.AssertNotError(t, err, "ra.NewOrder failed")
	test.AssertEquals(t, *orderB.RegistrationID, int64(1))
	test.AssertEquals(t, *orderB.Expires, fc.Now().Add(time.Hour).UnixNano())
	// We expect orderB's ID to match orderA's because of pending order reuse
	test.AssertEquals(t, *orderB.Id, *orderA.Id)
	test.AssertEquals(t, len(orderB.Names), 3)
	test.AssertDeepEquals(t, orderB.Names, []string{"a.com", "b.com", "c.com"})
	test.AssertEquals(t, numAuthorizations(orderB), 3)
	test.AssertDeepEquals(t, orderB.V2Authorizations, orderA.V2Authorizations)

	// Reuse all of the existing authorizations from the previous order and
	// add a new one
	orderA.Names = append(orderA.Names, "d.com")
	orderC, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
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
	test.AssertEquals(t, numAuthorizations(orderC), 4)
	// Abuse the order of the queries used to extract the reused authorizations
	existing := orderC.V2Authorizations[:3]
	test.AssertDeepEquals(t, existing, orderA.V2Authorizations)

	_, err = ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
		Names:          []string{"a"},
	})
	test.AssertError(t, err, "NewOrder with invalid names did not error")
	test.AssertEquals(t, err.Error(), "Cannot issue for \"a\": Domain name needs at least one dot")
}

// TestNewOrderLegacyAuthzReuse tests that a legacy acme v1 authorization from
// the `new-authz` endpoint isn't reused by a V2 order created by the same
// account.
func TestNewOrderLegacyAuthzReuse(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.orderLifetime = time.Hour

	// Create a legacy pending authz, not associated with an order
	exp := ra.clk.Now().Add(365 * 24 * time.Hour)
	authzID := createFinalizedAuthorization(t, sa, "not-example.com", exp, "valid")

	// Create an order request for the same name as the legacy authz
	order, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
		Names:          []string{"not-example.com"},
	})
	// It should not produce an error
	test.AssertNotError(t, err, "ra.NewOrder failed")
	// There should be only one authorization
	test.AssertEquals(t, numAuthorizations(order), 1)
	// The authorization should not be the legacy authz
	test.AssertNotEquals(t, order.V2Authorizations[0], authzID)
	// The order should be pending status
	test.AssertEquals(t, *order.Status, string(core.StatusPending))

	// Create an order request for a superset of the names from the order above to
	// test that V2 reuse still functions.
	secondOrder, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
		Names:          []string{"not-example.com", "deffo.not-example.com"},
	})
	// It should not produce an error
	test.AssertNotError(t, err, "ra.NewOrder failed")
	// There should be only two authorizations
	test.AssertEquals(t, numAuthorizations(secondOrder), 2)

	// Check each of the authorizations
	// If the ID is equal to the original order's authorization ID then the
	// authz was reused
	reusedAuthz := secondOrder.V2Authorizations[0] == order.V2Authorizations[0]
	// We expect the authz to have been reused.
	test.AssertEquals(t, reusedAuthz, true)
}

// TestNewOrderReuse tests that subsequent requests by an ACME account to create
// an identical order results in only one order being created & subsequently
// reused.
func TestNewOrderReuse(t *testing.T) {
	_, _, ra, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	ctx := context.Background()
	names := []string{"zombo.com", "welcome.to.zombo.com"}

	// Configure the RA to use a short order lifetime
	ra.orderLifetime = time.Hour
	// Create a var with two times the order lifetime to reference later
	doubleLifetime := ra.orderLifetime * 2

	// Create an initial request with regA and names
	orderReq := &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
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
				RegistrationID: Registration.ID,
				Names:          []string{names[1]},
			},
			// We do not expect reuse because the order names don't match firstOrder
			ExpectReuse: false,
		},
		{
			Name: "Duplicate order, different regID",
			OrderReq: &rapb.NewOrderRequest{
				RegistrationID: secondReg.ID,
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
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	ctx := context.Background()
	names := []string{"zombo.com"}

	// Create an initial request with regA and names
	orderReq := &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
		Names:          names,
	}

	// First, add an order with `names` for regA
	order, err := ra.NewOrder(ctx, orderReq)
	// It shouldn't fail
	test.AssertNotError(t, err, "Adding an initial order for regA failed")
	// It should have an ID
	test.AssertNotNil(t, order.Id, "Initial order had a nil ID")
	// It should have one authorization
	test.AssertEquals(t, numAuthorizations(order), 1)

	err = ra.SA.FinalizeAuthorization2(ctx, &sapb.FinalizeAuthorizationRequest{
		Id:        order.V2Authorizations[0],
		Status:    string(core.StatusInvalid),
		Expires:   *order.Expires,
		Attempted: string(core.ChallengeTypeDNS01),
	})
	test.AssertNotError(t, err, "FinalizeAuthorization2 failed")

	// The order associated with the authz should now be invalid
	updatedOrder, err := ra.SA.GetOrder(ctx, &sapb.OrderRequest{Id: *order.Id})
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
	test.AssertEquals(t, numAuthorizations(secondOrder), 1)
	// It should have a different authorization than the first order's now-invalid authorization
	test.AssertNotEquals(t, secondOrder.V2Authorizations[0], order.V2Authorizations[0])
}

// mockSAUnsafeAuthzReuse has a GetAuthorizations implementation that returns
// an HTTP-01 validated wildcard authz.
type mockSAUnsafeAuthzReuse struct {
	mocks.StorageAuthority
}

// GetAuthorizations returns a _bizarre_ authorization for "*.zombo.com" that
// was validated by HTTP-01. This should never happen in real life since the
// name is a wildcard. We use this mock to test that we reject this bizarre
// situation correctly.
func (msa *mockSAUnsafeAuthzReuse) GetAuthorizations(
	ctx context.Context,
	req *sapb.GetAuthorizationsRequest) (*sapb.Authorizations, error) {
	expires := time.Now()
	authzs := map[string]*core.Authorization{
		"*.zombo.com": {
			// A static fake ID we can check for in a unit test
			ID:             "bad-bad-not-good",
			Identifier:     identifier.DNSIdentifier("*.zombo.com"),
			RegistrationID: req.RegistrationID,
			// Authz is valid
			Status:  "valid",
			Expires: &expires,
			Challenges: []core.Challenge{
				// HTTP-01 challenge is valid
				{
					Type:   core.ChallengeTypeHTTP01, // The dreaded HTTP-01! X__X
					Status: core.StatusValid,
				},
				// DNS-01 challenge is pending
				{
					Type:   core.ChallengeTypeDNS01,
					Status: core.StatusPending,
				},
			},
		},
		"zombo.com": {
			// A static fake ID we can check for in a unit test
			ID:             "reused-valid-authz",
			Identifier:     identifier.DNSIdentifier("zombo.com"),
			RegistrationID: req.RegistrationID,
			// Authz is valid
			Status:  "valid",
			Expires: &expires,
			Challenges: []core.Challenge{
				// HTTP-01 challenge is valid
				{
					Type:   core.ChallengeTypeHTTP01,
					Status: core.StatusValid,
				},
				// DNS-01 challenge is pending
				{
					Type:   core.ChallengeTypeDNS01,
					Status: core.StatusPending,
				},
			},
		},
	}
	return sa.AuthzMapToPB(authzs)
}

func (msa *mockSAUnsafeAuthzReuse) GetAuthorizations2(
	ctx context.Context,
	req *sapb.GetAuthorizationsRequest) (*sapb.Authorizations, error) {
	expires := time.Now()
	authzs := map[string]*core.Authorization{
		"*.zombo.com": {
			// A static fake ID we can check for in a unit test
			ID:             "1",
			Identifier:     identifier.DNSIdentifier("*.zombo.com"),
			RegistrationID: req.RegistrationID,
			// Authz is valid
			Status:  "valid",
			Expires: &expires,
			Challenges: []core.Challenge{
				// HTTP-01 challenge is valid
				{
					Type:   core.ChallengeTypeHTTP01, // The dreaded HTTP-01! X__X
					Status: core.StatusValid,
				},
				// DNS-01 challenge is pending
				{
					Type:   core.ChallengeTypeDNS01,
					Status: core.StatusPending,
				},
			},
		},
		"zombo.com": {
			// A static fake ID we can check for in a unit test
			ID:             "2",
			Identifier:     identifier.DNSIdentifier("zombo.com"),
			RegistrationID: req.RegistrationID,
			// Authz is valid
			Status:  "valid",
			Expires: &expires,
			Challenges: []core.Challenge{
				// HTTP-01 challenge is valid
				{
					Type:   core.ChallengeTypeHTTP01,
					Status: core.StatusValid,
				},
				// DNS-01 challenge is pending
				{
					Type:   core.ChallengeTypeDNS01,
					Status: core.StatusPending,
				},
			},
		},
	}
	return sa.AuthzMapToPB(authzs)

}

// AddPendingAuthorizations is a mock that just returns a fake pending authz ID
// that is != "bad-bad-not-good"
func (sa *mockSAUnsafeAuthzReuse) AddPendingAuthorizations(
	_ context.Context,
	_ *sapb.AddPendingAuthorizationsRequest) (*sapb.AuthorizationIDs, error) {
	return &sapb.AuthorizationIDs{
		Ids: []string{
			"abcdefg",
		},
	}, nil
}

func (sa *mockSAUnsafeAuthzReuse) NewAuthorizations2(_ context.Context, _ *sapb.AddPendingAuthorizationsRequest) (*sapb.Authorization2IDs, error) {
	return &sapb.Authorization2IDs{
		Ids: []int64{5},
	}, nil
}

// TestNewOrderAuthzReuseSafety checks that the RA's safety check for reusing an
// authorization for a new-order request with a wildcard name works correctly.
// We want to ensure that we never reuse a non-Wildcard authorization (e.g. one
// with more than just a DNS-01 challenge) for a wildcard name. See Issue #3420
// for background - this safety check was previously broken!
// https://github.com/letsencrypt/boulder/issues/3420
func TestNewOrderAuthzReuseSafety(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	ctx := context.Background()
	names := []string{"*.zombo.com"}

	// Use a mock SA that always returns a valid HTTP-01 authz for the name
	// "zombo.com"
	ra.SA = &mockSAUnsafeAuthzReuse{}

	// Create an initial request with regA and names
	orderReq := &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
		Names:          names,
	}

	// Create an order for that request
	order, err := ra.NewOrder(ctx, orderReq)
	// It shouldn't fail
	test.AssertNotError(t, err, "Adding an initial order for regA failed")
	test.AssertEquals(t, numAuthorizations(order), 1)
	// It should *not* be the bad authorization!
	test.AssertNotEquals(t, order.V2Authorizations[0], int64(1))
}

func TestNewOrderAuthzReuseDisabled(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	ctx := context.Background()
	names := []string{"zombo.com"}

	// Use a mock SA that always returns a valid HTTP-01 authz for the name
	// "zombo.com"
	ra.SA = &mockSAUnsafeAuthzReuse{}

	// Disable authz reuse
	ra.reuseValidAuthz = false

	// Create an initial request with regA and names
	orderReq := &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
		Names:          names,
	}

	// Create an order for that request
	order, err := ra.NewOrder(ctx, orderReq)
	// It shouldn't fail
	test.AssertNotError(t, err, "Adding an initial order for regA failed")
	test.AssertEquals(t, numAuthorizations(order), 1)
	// It should *not* be the bad authorization that indicates reuse!
	test.AssertNotEquals(t, order.V2Authorizations[0], int64(2))
}

func TestNewOrderWildcard(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.orderLifetime = time.Hour

	orderNames := []string{"example.com", "*.welcome.zombo.com"}
	wildcardOrderRequest := &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
		Names:          orderNames,
	}

	order, err := ra.NewOrder(context.Background(), wildcardOrderRequest)
	test.AssertNotError(t, err, "NewOrder failed for a wildcard order request")

	// We expect the order to be pending
	test.AssertEquals(t, *order.Status, string(core.StatusPending))
	// We expect the order to have two names
	test.AssertEquals(t, len(order.Names), 2)
	// We expect the order to have the names we requested
	test.AssertDeepEquals(t,
		core.UniqueLowerNames(order.Names),
		core.UniqueLowerNames(orderNames))
	test.AssertEquals(t, numAuthorizations(order), 2)

	// Check each of the authz IDs in the order
	for _, authzID := range order.V2Authorizations {
		// We should be able to retrieve the authz from the db without error
		authzID := authzID
		authzPB, err := ra.SA.GetAuthorization2(ctx, &sapb.AuthorizationID2{Id: authzID})
		test.AssertNotError(t, err, "sa.GetAuthorization2 failed")
		authz, err := bgrpc.PBToAuthz(authzPB)
		test.AssertNotError(t, err, "bgrpc.PBToAuthz failed")

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
			test.AssertEquals(t, len(authz.Challenges), 2)
		default:
			t.Fatalf("Received an authorization for a name not requested: %q", name)
		}
	}

	// An order for a base domain and a wildcard for the same base domain should
	// return just 2 authz's, one for the wildcard with a DNS-01
	// challenge and one for the base domain with the normal challenges.
	orderNames = []string{"zombo.com", "*.zombo.com"}
	wildcardOrderRequest = &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
		Names:          orderNames,
	}
	order, err = ra.NewOrder(context.Background(), wildcardOrderRequest)
	test.AssertNotError(t, err, "NewOrder failed for a wildcard order request")

	// We expect the order to be pending
	test.AssertEquals(t, *order.Status, string(core.StatusPending))
	// We expect the order to have two names
	test.AssertEquals(t, len(order.Names), 2)
	// We expect the order to have the names we requested
	test.AssertDeepEquals(t,
		core.UniqueLowerNames(order.Names),
		core.UniqueLowerNames(orderNames))
	test.AssertEquals(t, numAuthorizations(order), 2)

	for _, authzID := range order.V2Authorizations {
		// We should be able to retrieve the authz from the db without error
		authzID := authzID
		authzPB, err := ra.SA.GetAuthorization2(ctx, &sapb.AuthorizationID2{Id: authzID})
		test.AssertNotError(t, err, "sa.GetAuthorization2 failed")
		authz, err := bgrpc.PBToAuthz(authzPB)
		test.AssertNotError(t, err, "bgrpc.PBToAuthz failed")
		// We expect the authz is in Pending status
		test.AssertEquals(t, authz.Status, core.StatusPending)
		switch authz.Identifier.Value {
		case "zombo.com":
			// We expect that the base domain identifier auth has the normal number of
			// challenges
			test.AssertEquals(t, len(authz.Challenges), 2)
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
		RegistrationID: Registration.ID,
		Names:          []string{"everything.is.possible.zombo.com"},
	}
	normalOrder, err := ra.NewOrder(context.Background(), normalOrderReq)
	test.AssertNotError(t, err, "NewOrder failed for a normal non-wildcard order")

	test.AssertEquals(t, numAuthorizations(normalOrder), 1)
	// We expect the order is in Pending status
	test.AssertEquals(t, *order.Status, string(core.StatusPending))
	var authz core.Authorization
	authzPB, err := ra.SA.GetAuthorization2(ctx, &sapb.AuthorizationID2{Id: normalOrder.V2Authorizations[0]})
	test.AssertNotError(t, err, "sa.GetAuthorization2 failed")
	authz, err = bgrpc.PBToAuthz(authzPB)
	test.AssertNotError(t, err, "bgrpc.PBToAuthz failed")
	// We expect the authz is in Pending status
	test.AssertEquals(t, authz.Status, core.StatusPending)
	// We expect the authz is for the identifier the correct domain
	test.AssertEquals(t, authz.Identifier.Value, "everything.is.possible.zombo.com")
	// We expect the authz has the normal # of challenges
	test.AssertEquals(t, len(authz.Challenges), 2)

	// Now submit an order request for a wildcard of the domain we just created an
	// order for. We should **NOT** reuse the authorization from the previous
	// order since we now require a DNS-01 challenge for the `*.` prefixed name.
	orderNames = []string{"*.everything.is.possible.zombo.com"}
	wildcardOrderRequest = &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
		Names:          orderNames,
	}
	order, err = ra.NewOrder(context.Background(), wildcardOrderRequest)
	test.AssertNotError(t, err, "NewOrder failed for a wildcard order request")
	// We expect the order is in Pending status
	test.AssertEquals(t, *order.Status, string(core.StatusPending))
	test.AssertEquals(t, numAuthorizations(order), 1)
	// The authz should be a different ID than the previous authz
	test.AssertNotEquals(t, order.V2Authorizations[0], normalOrder.V2Authorizations[0])
	// We expect the authorization is available
	authzPB, err = ra.SA.GetAuthorization2(ctx, &sapb.AuthorizationID2{Id: order.V2Authorizations[0]})
	test.AssertNotError(t, err, "sa.GetAuthorization2 failed")
	authz, err = bgrpc.PBToAuthz(authzPB)
	test.AssertNotError(t, err, "bgrpc.PBToAuthz failed")
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
	test.AssertNotError(t, err, "NewOrder failed for a wildcard order request")
	// We expect the order is in Pending status
	test.AssertEquals(t, *dupeOrder.Status, string(core.StatusPending))
	test.AssertEquals(t, numAuthorizations(dupeOrder), 1)
	// The authz should be the same ID as the previous order's authz. We already
	// checked that order.Authorizations[0] only has a DNS-01 challenge above so
	// we don't need to recheck that here.
	test.AssertEquals(t, dupeOrder.V2Authorizations[0], order.V2Authorizations[0])
}

// mockSANearExpiredAuthz is a mock SA that always returns an authz near expiry
// to test orders expiry calculations
type mockSANearExpiredAuthz struct {
	mocks.StorageAuthority
	expiry time.Time
}

// GetAuthorizations is a mock that always returns a valid authorization for
// "zombo.com" very near to expiry
func (msa *mockSANearExpiredAuthz) GetAuthorizations(
	ctx context.Context,
	req *sapb.GetAuthorizationsRequest) (*sapb.Authorizations, error) {
	authzs := map[string]*core.Authorization{
		"zombo.com": {
			// A static fake ID we can check for in a unit test
			ID:             "near-expired-authz",
			Identifier:     identifier.DNSIdentifier("zombo.com"),
			RegistrationID: req.RegistrationID,
			Expires:        &msa.expiry,
			Status:         "valid",
			Challenges: []core.Challenge{
				{
					Type:   core.ChallengeTypeHTTP01,
					Status: core.StatusValid,
				},
			},
		},
	}
	return sa.AuthzMapToPB(authzs)
}

func (msa *mockSANearExpiredAuthz) GetAuthorizations2(
	ctx context.Context,
	req *sapb.GetAuthorizationsRequest) (*sapb.Authorizations, error) {
	authzs := map[string]*core.Authorization{
		"zombo.com": {
			// A static fake ID we can check for in a unit test
			ID:             "1",
			Identifier:     identifier.DNSIdentifier("zombo.com"),
			RegistrationID: req.RegistrationID,
			Expires:        &msa.expiry,
			Status:         "valid",
			Challenges: []core.Challenge{
				{
					Type:   core.ChallengeTypeHTTP01,
					Status: core.StatusValid,
				},
			},
		},
	}
	return sa.AuthzMapToPB(authzs)
}

// AddPendingAuthorizations is a mock that just returns a fake pending authz ID
// that is != "near-expired-authz"
func (msa *mockSANearExpiredAuthz) AddPendingAuthorizations(
	_ context.Context,
	_ *sapb.AddPendingAuthorizationsRequest) (*sapb.AuthorizationIDs, error) {
	return &sapb.AuthorizationIDs{
		Ids: []string{
			"abcdefg",
		},
	}, nil
}

func (msa *mockSANearExpiredAuthz) NewAuthorizations2(_ context.Context, _ *sapb.AddPendingAuthorizationsRequest) (*sapb.Authorization2IDs, error) {
	return &sapb.Authorization2IDs{
		Ids: []int64{5},
	}, nil
}

func TestNewOrderExpiry(t *testing.T) {
	_, _, ra, clk, cleanUp := initAuthorities(t)
	defer cleanUp()

	ctx := context.Background()
	names := []string{"zombo.com"}

	// Set the order lifetime to 48 hours.
	ra.orderLifetime = 48 * time.Hour

	// Use an expiry that is sooner than the configured order expiry but greater
	// than 24 hours away.
	fakeAuthzExpires := clk.Now().Add(35 * time.Hour)

	// Use a mock SA that always returns a soon-to-be-expired valid authz for
	// "zombo.com".
	ra.SA = &mockSANearExpiredAuthz{expiry: fakeAuthzExpires}

	// Create an initial request with regA and names
	orderReq := &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
		Names:          names,
	}

	// Create an order for that request
	order, err := ra.NewOrder(ctx, orderReq)
	// It shouldn't fail
	test.AssertNotError(t, err, "Adding an order for regA failed")
	test.AssertEquals(t, numAuthorizations(order), 1)
	// It should be the fake near-expired-authz authz
	test.AssertEquals(t, order.V2Authorizations[0], int64(1))
	// The order's expiry should be the fake authz's expiry since it is sooner
	// than the order's own expiry.
	test.AssertEquals(t, *order.Expires, fakeAuthzExpires.UnixNano())

	// Set the order lifetime to be lower than the fakeAuthzLifetime
	ra.orderLifetime = 12 * time.Hour
	expectedOrderExpiry := clk.Now().Add(ra.orderLifetime).UnixNano()
	// Create the order again
	order, err = ra.NewOrder(ctx, orderReq)
	// It shouldn't fail
	test.AssertNotError(t, err, "Adding an order for regA failed")
	test.AssertEquals(t, numAuthorizations(order), 1)
	// It should be the fake near-expired-authz authz
	test.AssertEquals(t, order.V2Authorizations[0], int64(1))
	// The order's expiry should be the order's own expiry since it is sooner than
	// the fake authz's expiry.
	test.AssertEquals(t, *order.Expires, expectedOrderExpiry)
}

func TestFinalizeOrder(t *testing.T) {
	_, sa, ra, fc, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.orderLifetime = time.Hour

	validStatus := string(core.StatusValid)
	pendingStatus := string(core.StatusPending)
	readyStatus := string(core.StatusReady)
	processingStatus := false

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

	// Create one finalized authorization for not-example.com and one finalized
	// authorization for www.not-example.org
	exp := ra.clk.Now().Add(365 * 24 * time.Hour)
	authzIDA := createFinalizedAuthorization(t, sa, "not-example.com", exp, "valid")
	authzIDB := createFinalizedAuthorization(t, sa, "www.not-example.com", exp, "valid")

	// Create an order with valid authzs, it should end up status ready in the
	// resulting returned order
	expUnix := exp.UnixNano()
	modernFinalOrder, err := sa.NewOrder(context.Background(), &corepb.Order{
		RegistrationID:   &Registration.ID,
		Expires:          &expUnix,
		Names:            []string{"not-example.com", "www.not-example.com"},
		V2Authorizations: []int64{authzIDA, authzIDB},
		Status:           &readyStatus,
		BeganProcessing:  &processingStatus,
	})
	test.AssertNotError(t, err, "Could not add test order with finalized authz IDs, ready status")

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate test key")
	validCSR := &x509.CertificateRequest{
		PublicKey: k.Public(),
		DNSNames:  []string{"not-example.com", "www.not-example.com"},
	}
	validCSRDER, err := x509.CreateCertificateRequest(rand.Reader, validCSR, k)
	test.AssertNotError(t, err, "failed to construct csr")
	expectedCert := &x509.Certificate{
		SerialNumber:          big.NewInt(0),
		Subject:               pkix.Name{CommonName: "not-example.com"},
		DNSNames:              []string{"not-example.com", "www.not-example.com"},
		PublicKey:             k.Public(),
		NotBefore:             fc.Now(),
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, expectedCert, expectedCert, k.Public(), k)
	test.AssertNotError(t, err, "failed to construct test certificate")
	ra.CA.(*mocks.MockCA).PEM = pem.EncodeToMemory(&pem.Block{Bytes: certDER, Type: "CERTIFICATE"})

	fakeRegID := int64(0xB00)

	// NOTE(@cpu): We use unique `names` for each of these orders because
	// otherwise only *one* order is created & reused. The first test case to
	// finalize the order will put it into processing state and the other tests
	// will fail because you can't finalize an order that is already being
	// processed.
	emptyOrder, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
		Names:          []string{"000.example.com"},
	})
	test.AssertNotError(t, err, "Could not add test order for fake order ID")

	// Add a new order for the fake reg ID
	fakeRegOrder, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
		Names:          []string{"001.example.com"},
	})
	test.AssertNotError(t, err, "Could not add test order for fake reg ID order ID")

	missingAuthzOrder, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.ID,
		Names:          []string{"002.example.com"},
	})
	test.AssertNotError(t, err, "Could not add test order for missing authz order ID")

	emptyStr := ""
	falseBool := false
	fakeCreated := ra.clk.Now().UnixNano()

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
					Status: &readyStatus,
					Names:  []string{},
				},
			},
			ExpectedErrMsg: "Order has no associated names",
		},
		{
			Name: "Wrong order state (valid)",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Status: &validStatus,
					Names:  []string{"example.com"},
				},
			},
			ExpectedErrMsg: `Order's status ("valid") is not acceptable for finalization`,
		},
		{
			Name: "Wrong order state (pending)",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Status: &pendingStatus,
					Names:  []string{"example.com"},
				},
				Csr: validCSRDER,
			},
			ExpectIssuance: false,
			ExpectedErrMsg: `Order's status ("pending") is not acceptable for finalization`,
		},
		{
			Name: "Invalid CSR",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Status: &readyStatus,
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
					Status:         &readyStatus,
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
					Status:         &readyStatus,
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
					Status:            &readyStatus,
					Names:             []string{"example.org"},
					RegistrationID:    &Registration.ID,
					Id:                emptyOrder.Id,
					Expires:           &expUnix,
					CertificateSerial: &emptyStr,
					BeganProcessing:   &falseBool,
				},
				Csr: policyForbidCSR,
			},
			ExpectedErrMsg: "Cannot issue for \"example.org\": The ACME server refuses to issue a certificate for this domain name, because it is forbidden by policy",
		},
		{
			Name: "Order with missing registration",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Status:            &readyStatus,
					Names:             []string{"a.com", "a.org"},
					Id:                fakeRegOrder.Id,
					RegistrationID:    &fakeRegID,
					Expires:           &expUnix,
					CertificateSerial: &emptyStr,
					BeganProcessing:   &falseBool,
					Created:           &fakeCreated,
				},
				Csr: twoDomainCSR,
			},
			ExpectedErrMsg: fmt.Sprintf("registration with ID '%d' not found", fakeRegID),
		},
		{
			Name: "Order with missing authorizations",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Status:            &readyStatus,
					Names:             []string{"a.com", "a.org", "b.com"},
					Id:                missingAuthzOrder.Id,
					RegistrationID:    &Registration.ID,
					Expires:           &expUnix,
					CertificateSerial: &emptyStr,
					BeganProcessing:   &falseBool,
					Created:           &fakeCreated,
				},
				Csr: threeDomainCSR,
			},
			ExpectedErrMsg: "authorizations for these names not found or expired: a.com, a.org, b.com",
		},
		{
			Name: "Order with correct authorizations, ready status",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: modernFinalOrder,
				Csr:   validCSRDER,
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
					&sapb.OrderRequest{Id: *tc.OrderReq.Order.Id})
				test.AssertNotError(t, err, "Error getting order to check serial")
				test.AssertNotEquals(t, *updatedOrder.CertificateSerial, "")
				test.AssertEquals(t, *updatedOrder.Status, "valid")
			}
		})
	}
}

func TestFinalizeOrderWithMixedSANAndCN(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.orderLifetime = time.Hour

	// Pick an expiry in the future
	exp := ra.clk.Now().Add(365 * 24 * time.Hour)

	// Create one finalized authorization for Registration.ID for not-example.com and
	// one finalized authorization for Registration.ID for www.not-example.org
	authzIDA := createFinalizedAuthorization(t, sa, "not-example.com", exp, "valid")
	authzIDB := createFinalizedAuthorization(t, sa, "www.not-example.com", exp, "valid")

	// Create a new order to finalize with names in SAN and CN
	expUnix := exp.UnixNano()
	pendingStatus := "pending"
	mixedOrder, err := sa.NewOrder(context.Background(), &corepb.Order{
		RegistrationID:   &Registration.ID,
		Expires:          &expUnix,
		Names:            []string{"not-example.com", "www.not-example.com"},
		V2Authorizations: []int64{authzIDA, authzIDB},
		Status:           &pendingStatus,
	})
	test.AssertNotError(t, err, "Could not add test order with finalized authz IDs")
	testKey, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "error generating test key")
	mixedCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		PublicKey:          testKey.PublicKey,
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject:            pkix.Name{CommonName: "not-example.com"},
		DNSNames:           []string{"www.not-example.com"},
	}, testKey)
	test.AssertNotError(t, err, "Could not create mixed CSR")

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(12),
		Subject:               pkix.Name{CommonName: "not-example.com"},
		DNSNames:              []string{"www.not-example.com", "not-example.com"},
		NotBefore:             time.Now(),
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, testKey.Public(), testKey)
	test.AssertNotError(t, err, "Failed to create mixed cert")

	ra.CA = &mocks.MockCA{
		PEM: pem.EncodeToMemory(&pem.Block{
			Bytes: cert,
		}),
	}

	_, result := ra.FinalizeOrder(context.Background(), &rapb.FinalizeOrderRequest{Order: mixedOrder, Csr: mixedCSR})
	test.AssertNotError(t, result, "FinalizeOrder failed")
	// Check that the order now has a serial for the issued certificate
	updatedOrder, err := sa.GetOrder(
		context.Background(),
		&sapb.OrderRequest{Id: *mixedOrder.Id})
	test.AssertNotError(t, err, "Error getting order to check serial")
	test.AssertNotEquals(t, *updatedOrder.CertificateSerial, "")
	test.AssertEquals(t, *updatedOrder.Status, "valid")
}

func TestFinalizeOrderWildcard(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Pick an expiry in the future
	exp := ra.clk.Now().Add(365 * 24 * time.Hour)

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
		Subject:               pkix.Name{CommonName: "*.zombo.com"},
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
		RegistrationID: Registration.ID,
		Names:          orderNames,
	}
	order, err := ra.NewOrder(context.Background(), wildcardOrderRequest)
	test.AssertNotError(t, err, "NewOrder failed for wildcard domain order")

	// Create one standard finalized authorization for Registration.ID for zombo.com
	_ = createFinalizedAuthorization(t, sa, "zombo.com", exp, "valid")

	// Finalizing the order should *not* work since the existing validated authz
	// is not a special DNS-01-Wildcard challenge authz, so the order will be
	// "pending" not "ready".
	finalizeReq := &rapb.FinalizeOrderRequest{
		Order: order,
		Csr:   wildcardCSR,
	}
	_, err = ra.FinalizeOrder(context.Background(), finalizeReq)
	test.AssertError(t, err, "FinalizeOrder did not fail for unauthorized "+
		"wildcard order")
	test.AssertEquals(t, err.Error(),
		`Order's status ("pending") is not acceptable for finalization`)

	// Creating another order for the wildcard name
	validOrder, err := ra.NewOrder(context.Background(), wildcardOrderRequest)
	test.AssertNotError(t, err, "NewOrder failed for wildcard domain order")
	test.AssertEquals(t, numAuthorizations(validOrder), 1)
	// We expect to be able to get the authorization by ID
	_, err = sa.GetAuthorization2(ctx, &sapb.AuthorizationID2{Id: validOrder.V2Authorizations[0]})
	test.AssertNotError(t, err, "sa.GetAuthorization2 failed")

	// Finalize the authorization with the challenge validated
	err = sa.FinalizeAuthorization2(ctx, &sapb.FinalizeAuthorizationRequest{
		Id:        validOrder.V2Authorizations[0],
		Status:    string(core.StatusValid),
		Expires:   ra.clk.Now().Add(time.Hour * 24 * 7).UnixNano(),
		Attempted: string(core.ChallengeTypeDNS01),
	})
	test.AssertNotError(t, err, "sa.FinalizeAuthorization2 failed")

	// Refresh the order so the SA sets its status
	validOrder, err = sa.GetOrder(ctx, &sapb.OrderRequest{
		Id: *validOrder.Id,
	})
	test.AssertNotError(t, err, "Could not refresh valid order from SA")

	// Now it should be possible to finalize the order
	finalizeReq = &rapb.FinalizeOrderRequest{
		Order: validOrder,
		Csr:   wildcardCSR,
	}
	_, err = ra.FinalizeOrder(context.Background(), finalizeReq)
	test.AssertNotError(t, err, "FinalizeOrder failed for authorized "+
		"wildcard order")
}

func TestIssueCertificateAuditLog(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Set up order and authz expiries
	ra.orderLifetime = 24 * time.Hour
	exp := ra.clk.Now().Add(24 * time.Hour)

	authzForChalType := func(domain, chalType string) int64 {
		template := core.Authorization{
			Identifier: identifier.ACMEIdentifier{
				Type:  "dns",
				Value: domain,
			},
			RegistrationID: Registration.ID,
			Status:         "pending",
			Expires:        &exp,
		}
		// Create challenges
		token := core.NewToken()
		httpChal := core.HTTPChallenge01(token)
		dnsChal := core.DNSChallenge01(token)
		// Set the selected challenge to valid
		switch chalType {
		case "http-01":
			httpChal.Status = core.StatusValid
		case "dns-01":
			dnsChal.Status = core.StatusValid
		default:
			t.Fatalf("Invalid challenge type used with authzForChalType: %q", chalType)
		}
		// Set the template's challenges
		template.Challenges = []core.Challenge{httpChal, dnsChal}

		// Create the pending authz
		authzPB, err := bgrpc.AuthzToPB(template)
		test.AssertNotError(t, err, "bgrpc.AuthzToPB failed")
		ids, err := sa.NewAuthorizations2(ctx, &sapb.AddPendingAuthorizationsRequest{
			Authz: []*corepb.Authorization{authzPB},
		})
		test.AssertNotError(t, err, "sa.NewAuthorzations2 failed")
		// Finalize the authz
		err = sa.FinalizeAuthorization2(ctx, &sapb.FinalizeAuthorizationRequest{
			Id:        ids.Ids[0],
			Status:    "valid",
			Expires:   exp.UnixNano(),
			Attempted: chalType,
		})
		test.AssertNotError(t, err, "sa.FinalizeAuthorization2 failed")
		return ids.Ids[0]
	}

	// Make some valid authorizations for some names using different challenge types
	names := []string{"not-example.com", "www.not-example.com", "still.not-example.com", "definitely.not-example.com"}
	chalTypes := []string{"http-01", "dns-01", "http-01", "dns-01"}
	var authzIDs []int64
	for i, name := range names {
		authzIDs = append(authzIDs, authzForChalType(name, chalTypes[i]))
	}

	// Create a pending order for all of the names
	expUnix := exp.Unix()
	pendingStatus := "pending"
	order, err := sa.NewOrder(context.Background(), &corepb.Order{
		RegistrationID:   &Registration.ID,
		Expires:          &expUnix,
		Names:            names,
		V2Authorizations: authzIDs,
		Status:           &pendingStatus,
	})
	test.AssertNotError(t, err, "Could not add test order with finalized authz IDs")

	// Generate a CSR covering the order names with a random RSA key
	testKey, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "error generating test key")
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		PublicKey:          testKey.PublicKey,
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject:            pkix.Name{CommonName: "not-example.com"},
		DNSNames:           names,
	}, testKey)
	test.AssertNotError(t, err, "Could not create test order CSR")

	// Create a mock certificate for the fake CA to return
	template := &x509.Certificate{
		SerialNumber: big.NewInt(12),
		Subject: pkix.Name{
			CommonName: "not-example.com",
		},
		DNSNames:              names,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 1),
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, testKey.Public(), testKey)
	test.AssertNotError(t, err, "Failed to create mock cert for test CA")

	// Set up the RA's CA with a mock that returns the cert from above
	ra.CA = &mocks.MockCA{
		PEM: pem.EncodeToMemory(&pem.Block{
			Bytes: cert,
		}),
	}

	// The mock cert needs to be parsed to get its notbefore/notafter dates
	parsedCerts, err := x509.ParseCertificates(cert)
	test.AssertNotError(t, err, "Failed to parse mock cert DER bytes")
	test.AssertEquals(t, len(parsedCerts), 1)
	parsedCert := parsedCerts[0]

	// Cast the RA's mock log so we can ensure its cleared and can access the
	// matched log lines
	mockLog := ra.log.(*blog.Mock)
	mockLog.Clear()

	// Finalize the order with the CSR
	status := string(core.StatusReady)
	order.Status = &status
	_, err = ra.FinalizeOrder(context.Background(), &rapb.FinalizeOrderRequest{
		Order: order,
		Csr:   csr,
	})
	test.AssertNotError(t, err, "Error finalizing test order")

	// Get the logged lines from the audit logger
	loglines := mockLog.GetAllMatching("Certificate request - successful JSON=")

	// There should be exactly 1 matching log line
	test.AssertEquals(t, len(loglines), 1)
	// Strip away the stuff before 'JSON='
	jsonContent := strings.TrimPrefix(loglines[0], "INFO: [AUDIT] Certificate request - successful JSON=")

	// Unmarshal the JSON into a certificate request event object
	var event certificateRequestEvent
	err = json.Unmarshal([]byte(jsonContent), &event)
	// The JSON should unmarshal without error
	test.AssertNotError(t, err, "Error unmarshalling logged JSON issuance event")
	// The event should have no error
	test.AssertEquals(t, event.Error, "")
	// The event requester should be the expected reg ID
	test.AssertEquals(t, event.Requester, Registration.ID)
	// The event order ID should be the expected order ID
	test.AssertEquals(t, event.OrderID, *order.Id)
	// The event serial number should be the expected serial number
	test.AssertEquals(t, event.SerialNumber, core.SerialToString(template.SerialNumber))
	// The event verified fields should be the expected value
	test.AssertDeepEquals(t, event.VerifiedFields, []string{"subject.commonName", "subjectAltName"})
	// The event CommonName should match the expected common name
	test.AssertEquals(t, event.CommonName, "not-example.com")
	// The event names should match the order names
	test.AssertDeepEquals(t, core.UniqueLowerNames(event.Names), core.UniqueLowerNames(order.Names))
	// The event's NotBefore and NotAfter should match the cert's
	test.AssertEquals(t, event.NotBefore, parsedCert.NotBefore)
	test.AssertEquals(t, event.NotAfter, parsedCert.NotAfter)

	// There should be one event Authorization entry for each name
	test.AssertEquals(t, len(event.Authorizations), len(names))

	// Check the authz entry for each name
	for i, name := range names {
		authzEntry := event.Authorizations[name]
		// The authz entry should have the correct authz ID
		test.AssertEquals(t, authzEntry.ID, fmt.Sprintf("%d", authzIDs[i]))
		// The authz entry should have the correct challenge type
		test.AssertEquals(t, string(authzEntry.ChallengeType), chalTypes[i])
	}
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
	err = ra.recordValidation(ctx, authz.ID, authz.Expires, &authz.Challenges[0])
	test.AssertNotError(t, err, "ra.recordValidation failed")

	err = ra.recordValidation(ctx, authz.ID, authz.Expires, &authz.Challenges[0])
	test.AssertError(t, err, "ra.recordValidation didn't fail")
	// It should *not* be an internal server error
	test.AssertEquals(t, berrors.Is(err, berrors.InternalServer), false)
	// It *should* be a NotFound error
	test.AssertEquals(t, berrors.Is(err, berrors.NotFound), true)
}

func TestValidChallengeStillGood(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	pa, err := policy.New(map[core.AcmeChallenge]bool{
		core.ChallengeTypeHTTP01: true,
	})
	test.AssertNotError(t, err, "Couldn't create PA")
	ra.PA = pa

	test.Assert(t, !ra.authzValidChallengeEnabled(&core.Authorization{}), "ra.authzValidChallengeEnabled didn't fail with empty authorization")
	test.Assert(t, !ra.authzValidChallengeEnabled(&core.Authorization{Challenges: []core.Challenge{{Status: core.StatusPending}}}), "ra.authzValidChallengeEnabled didn't fail with no valid challenges")
	test.Assert(t, !ra.authzValidChallengeEnabled(&core.Authorization{Challenges: []core.Challenge{{Status: core.StatusValid, Type: core.ChallengeTypeDNS01}}}), "ra.authzValidChallengeEnabled didn't fail with disabled challenge")
}

func TestPerformValidationBadChallengeType(t *testing.T) {
	_, _, ra, fc, cleanUp := initAuthorities(t)
	defer cleanUp()
	pa, err := policy.New(map[core.AcmeChallenge]bool{})
	test.AssertNotError(t, err, "Couldn't create PA")
	ra.PA = pa

	exp := fc.Now().Add(10 * time.Hour)
	authz := core.Authorization{
		Challenges: []core.Challenge{
			{
				Status: core.StatusValid,
				Type:   core.ChallengeTypeHTTP01,
				Token:  "exampleToken",
			},
		},
		Expires: &exp,
	}
	authzPB, err := bgrpc.AuthzToPB(authz)
	test.AssertNotError(t, err, "AuthzToPB failed")

	_, err = ra.PerformValidation(context.Background(), &rapb.PerformValidationRequest{
		Authz:          authzPB,
		ChallengeIndex: 0,
	})
	test.AssertError(t, err, "ra.PerformValidation allowed a update to a authorization")
	test.AssertEquals(t, err.Error(), "challenge type \"http-01\" no longer allowed")
}

type timeoutPub struct {
}

func (mp *timeoutPub) SubmitToSingleCTWithResult(_ context.Context, _ *pubpb.Request) (*pubpb.Result, error) {
	return nil, context.DeadlineExceeded
}

func TestCTPolicyMeasurements(t *testing.T) {
	_, ssa, _, fc, cleanup := initAuthorities(t)
	defer cleanup()
	stats := metrics.NoopRegisterer

	ca := &mocks.MockCA{
		PEM: eeCertPEM,
	}

	ctp := ctpolicy.New(&timeoutPub{}, []ctconfig.CTGroup{{}}, nil, log, metrics.NoopRegisterer)
	ra := NewRegistrationAuthorityImpl(fc,
		log,
		stats,
		1, testKeyPolicy, 0, true, 300*24*time.Hour, 7*24*time.Hour, nil, noopCAA{}, 0, ctp, nil, nil)
	ra.SA = ssa
	ra.CA = ca

	exp := ra.clk.Now().Add(365 * 24 * time.Hour)
	// Create valid authorizatiosn for not-example.com and www.not-example.com
	_ = createFinalizedAuthorization(t, ssa, "not-example.com", exp, "valid")
	_ = createFinalizedAuthorization(t, ssa, "www.not-example.com", exp, "valid")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := ra.issueCertificate(ctx, core.CertificateRequest{
		CSR: ExampleCSR,
	}, accountID(Registration.ID), 0)
	test.AssertError(t, err, "ra.issueCertificate didn't fail when CTPolicy.GetSCTs timed out")
	test.AssertEquals(t, test.CountHistogramSamples(ra.ctpolicyResults.With(prometheus.Labels{"result": "failure"})), 1)
}

func TestWildcardOverlap(t *testing.T) {
	err := wildcardOverlap([]string{
		"*.example.com",
		"*.example.net",
	})
	if err != nil {
		t.Errorf("Got error %q, expected none", err)
	}
	err = wildcardOverlap([]string{
		"*.example.com",
		"*.example.net",
		"www.example.com",
	})
	if err == nil {
		t.Errorf("Got no error, expected one")
	}
	berr, ok := err.(*berrors.BoulderError)
	if !ok {
		t.Errorf("Error was wrong type: %T", err)
	}
	if berr.Type != berrors.Malformed {
		t.Errorf("Error was wrong BoulderError type: %d", berr.Type)
	}
	err = wildcardOverlap([]string{
		"*.foo.example.com",
		"*.example.net",
		"www.example.com",
	})
	if err != nil {
		t.Errorf("Got error %q, expected none", err)
	}
}

// mockCAFailPrecert is a mock CA that always returns an error from `IssuePrecertificate`
type mockCAFailPrecert struct {
	mocks.MockCA
	err error
}

func (ca *mockCAFailPrecert) IssuePrecertificate(
	_ context.Context,
	_ *capb.IssueCertificateRequest) (*capb.IssuePrecertificateResponse, error) {
	return nil, ca.err
}

// mockCAFailCertForPrecert is a mock CA that always returns an error from
// `IssueCertificateForPrecertificate`
type mockCAFailCertForPrecert struct {
	mocks.MockCA
	err error
}

// IssuePrecertificate needs to be mocked for mockCAFailCertForPrecert's `IssueCertificateForPrecertificate` to get called.
func (ca *mockCAFailCertForPrecert) IssuePrecertificate(_ context.Context, _ *capb.IssueCertificateRequest) (*capb.IssuePrecertificateResponse, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &ctx509.Certificate{
		SerialNumber: big.NewInt(1),
		ExtraExtensions: []ctpkix.Extension{
			{
				Id:       ctx509.OIDExtensionCTPoison,
				Critical: true,
				Value:    ctasn1.NullBytes,
			},
		},
	}
	precert, err := ctx509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		return nil, err
	}
	return &capb.IssuePrecertificateResponse{
		DER: precert,
	}, nil
}

func (ca *mockCAFailCertForPrecert) IssueCertificateForPrecertificate(
	_ context.Context,
	_ *capb.IssueCertificateForPrecertificateRequest) (*corepb.Certificate, error) {
	return &corepb.Certificate{}, ca.err
}

// TestIssueCertificateInnerErrs tests that errors from the CA caught during
// `ra.issueCertificateInner` are propagated correctly, with the part of the
// issuance process that failed prefixed on the error message.
func TestIssueCertificateInnerErrs(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	ra.orderLifetime = 24 * time.Hour
	exp := ra.clk.Now().Add(24 * time.Hour)

	authzForIdent := func(domain string) int64 {
		template := core.Authorization{
			Identifier: identifier.ACMEIdentifier{
				Type:  "dns",
				Value: domain,
			},
			RegistrationID: Registration.ID,
			Status:         "pending",
			Expires:        &exp,
		}
		// Create one valid HTTP challenge
		httpChal := core.HTTPChallenge01(core.NewToken())
		httpChal.Status = core.StatusValid
		// Set the template's challenges
		template.Challenges = []core.Challenge{httpChal}
		// Create the pending authz
		authzPB, err := bgrpc.AuthzToPB(template)
		test.AssertNotError(t, err, "bgrpc.AuthzToPB failed")
		ids, err := sa.NewAuthorizations2(ctx, &sapb.AddPendingAuthorizationsRequest{
			Authz: []*corepb.Authorization{authzPB},
		})
		test.AssertNotError(t, err, "sa.NewAuthorzations2 failed")
		// Finalize the authz
		attempted := string(httpChal.Type)
		err = sa.FinalizeAuthorization2(ctx, &sapb.FinalizeAuthorizationRequest{
			Id:        ids.Ids[0],
			Status:    "valid",
			Expires:   exp.UnixNano(),
			Attempted: attempted,
		})
		test.AssertNotError(t, err, "sa.FinalizeAuthorization2 failed")
		return ids.Ids[0]
	}

	// Make some valid authorizations for some names
	names := []string{"not-example.com", "www.not-example.com", "still.not-example.com", "definitely.not-example.com"}
	var authzIDs []int64
	for _, name := range names {
		authzIDs = append(authzIDs, authzForIdent(name))
	}

	// Create a pending order for all of the names
	expUnix := exp.Unix()
	pendingStatus := "pending"
	order, err := sa.NewOrder(context.Background(), &corepb.Order{
		RegistrationID:   &Registration.ID,
		Expires:          &expUnix,
		Names:            names,
		V2Authorizations: authzIDs,
		Status:           &pendingStatus,
	})
	test.AssertNotError(t, err, "Could not add test order with finalized authz IDs")

	// Generate a CSR covering the order names with a random RSA key
	testKey, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "error generating test key")
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		PublicKey:          testKey.PublicKey,
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject:            pkix.Name{CommonName: "not-example.com"},
		DNSNames:           names,
	}, testKey)
	test.AssertNotError(t, err, "Could not create test order CSR")

	csrOb, err := x509.ParseCertificateRequest(csr)
	test.AssertNotError(t, err, "Error pasring generated CSR")

	req := core.CertificateRequest{
		Bytes: csr,
		CSR:   csrOb,
	}
	logEvent := &certificateRequestEvent{}

	testCases := []struct {
		Name         string
		Mock         core.CertificateAuthority
		ExpectedErr  error
		ExpectedProb *berrors.BoulderError
	}{
		{
			Name: "vanilla error during IssuePrecertificate",
			Mock: &mockCAFailPrecert{
				err: fmt.Errorf("bad bad not good"),
			},
			ExpectedErr: fmt.Errorf("issuing precertificate: bad bad not good"),
		},
		{
			Name: "malformed problem during IssuePrecertificate",
			Mock: &mockCAFailPrecert{
				err: berrors.MalformedError("detected 1x whack attack"),
			},
			ExpectedProb: &berrors.BoulderError{
				Detail: "issuing precertificate: detected 1x whack attack",
				Type:   berrors.Malformed,
			},
		},
		{
			Name: "vanilla error during IssueCertificateForPrecertificate",
			Mock: &mockCAFailCertForPrecert{
				err: fmt.Errorf("aaaaaaaaaaaaaaaaaaaa!!"),
			},
			ExpectedErr: fmt.Errorf("issuing certificate for precertificate: aaaaaaaaaaaaaaaaaaaa!!"),
		},
		{
			Name: "malformed problem during IssueCertificateForPrecertificate",
			Mock: &mockCAFailCertForPrecert{
				err: berrors.MalformedError("provided DER is DERanged"),
			},
			ExpectedProb: &berrors.BoulderError{
				Detail: "issuing certificate for precertificate: provided DER is DERanged",
				Type:   berrors.Malformed,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Mock the CA
			ra.CA = tc.Mock
			// Attempt issuance
			_, err = ra.issueCertificateInner(ctx, req, accountID(Registration.ID), orderID(*order.Id), logEvent)
			// We expect all of the testcases to fail because all use mocked CAs that deliberately error
			test.AssertError(t, err, "issueCertificateInner with failing mock CA did not fail")
			// If there is an expected `error` then match the error message
			if tc.ExpectedErr != nil {
				test.AssertEquals(t, err.Error(), tc.ExpectedErr.Error())
			} else if tc.ExpectedProb != nil {
				// If there is an expected `berrors.BoulderError` then we expect the
				// `issueCertificateInner` error to be a `berrors.BoulderError`
				berr, ok := err.(*berrors.BoulderError)
				if !ok {
					t.Fatalf("Expected a boulder error, got %#v\n", err)
				}
				// Match the expected berror Type and Detail to the observed
				test.AssertEquals(t, berr.Type, tc.ExpectedProb.Type)
				test.AssertEquals(t, berr.Detail, tc.ExpectedProb.Detail)
			}
		})
	}
}

type mockSAPreviousValidations struct {
	mocks.StorageAuthority
	existsDomain string
}

func (ms *mockSAPreviousValidations) PreviousCertificateExists(ctx context.Context, req *sapb.PreviousCertificateExistsRequest) (*sapb.Exists, error) {
	return &sapb.Exists{Exists: req.Domain == ms.existsDomain}, nil
}

func (ms *mockSAPreviousValidations) GetPendingAuthorization(_ context.Context, _ *sapb.GetPendingAuthorizationRequest) (*core.Authorization, error) {
	return nil, berrors.NotFoundError("")
}

func (ms *mockSAPreviousValidations) GetValidAuthorizations2(_ context.Context, _ *sapb.GetValidAuthorizationsRequest) (*sapb.Authorizations, error) {
	return &sapb.Authorizations{}, nil
}

func (ms *mockSAPreviousValidations) GetPendingAuthorization2(_ context.Context, _ *sapb.GetPendingAuthorizationRequest) (*corepb.Authorization, error) {
	return nil, berrors.NotFoundError("")
}

func (ms *mockSAPreviousValidations) NewAuthorizations2(_ context.Context, _ *sapb.AddPendingAuthorizationsRequest) (*sapb.Authorization2IDs, error) {
	return &sapb.Authorization2IDs{
		Ids: []int64{1},
	}, nil
}

func TestDisableNewV1Validations(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	ms := mockSAPreviousValidations{
		existsDomain: "bloop-example.com",
	}
	ra.SA = &ms

	_ = features.Set(map[string]bool{"V1DisableNewValidations": true})
	defer features.Reset()

	_, err := ra.NewAuthorization(context.Background(), core.Authorization{
		Identifier: identifier.DNSIdentifier("bloop-example.com"),
	}, 1)
	test.AssertNotError(t, err, "ra.NewAuthorization failed")

	_, err = ra.NewAuthorization(context.Background(), core.Authorization{
		Identifier: identifier.DNSIdentifier("bloop-not-example.com"),
	}, 1)
	test.AssertError(t, err, "ra.NewAuthorization failed")
	test.AssertEquals(t, err.Error(), "Validations for new domains are disabled in the V1 API (https://community.letsencrypt.org/t/end-of-life-plan-for-acmev1/88430)")
}

func TestNewOrderMaxNames(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	ra.maxNames = 2
	_, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		Names: []string{
			"a",
			"b",
			"c",
		},
	})
	test.AssertError(t, err, "NewOrder didn't fail with too many names in request")
	test.AssertEquals(t, err.Error(), "Order cannot contain more than 2 DNS names")
	test.AssertEquals(t, berrors.Is(err, berrors.Malformed), true)
}

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

type mockSABlockedKey struct {
	mocks.StorageAuthority

	added *sapb.AddBlockedKeyRequest
}

func (msabk *mockSABlockedKey) AddBlockedKey(_ context.Context, req *sapb.AddBlockedKeyRequest) (*corepb.Empty, error) {
	msabk.added = req
	return &corepb.Empty{}, nil
}

type mockCAOCSP struct {
	mocks.MockCA
}

func (mcao *mockCAOCSP) GenerateOCSP(context.Context, *capb.GenerateOCSPRequest) (*capb.OCSPResponse, error) {
	return &capb.OCSPResponse{Response: []byte{1, 2, 3}}, nil
}

type mockPurger struct{}

func (mp *mockPurger) Purge(context.Context, *akamaipb.PurgeRequest, ...grpc.CallOption) (*corepb.Empty, error) {
	return &corepb.Empty{}, nil
}

func TestRevocationAddBlockedKey(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	mockSA := mockSABlockedKey{}
	ra.SA = &mockSA
	ra.CA = &mockCAOCSP{}
	ra.purger = &mockPurger{}

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "ecdsa.GenerateKey failed")
	digest, err := core.KeyDigest(k.Public())
	test.AssertNotError(t, err, "core.KeyDigest failed")

	template := x509.Certificate{PublicKey: k, SerialNumber: big.NewInt(257)}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, k.Public(), k)
	test.AssertNotError(t, err, "x509.CreateCertificate failed")
	cert, err := x509.ParseCertificate(der)
	test.AssertNotError(t, err, "x509.ParseCertificate failed")
	ra.issuer = cert

	err = ra.RevokeCertificateWithReg(context.Background(), *cert, ocsp.Unspecified, 0)
	test.AssertNotError(t, err, "RevokeCertificateWithReg failed")
	test.Assert(t, mockSA.added == nil, "blocked key was added when reason was not keyCompromise")
	test.AssertEquals(t, test.CountCounterVec(
		"reason", "unspecified", ra.revocationReasonCounter), 1)

	err = ra.RevokeCertificateWithReg(context.Background(), *cert, ocsp.KeyCompromise, 0)
	test.AssertNotError(t, err, "RevokeCertificateWithReg failed")
	test.Assert(t, mockSA.added != nil, "blocked key was not added when reason was keyCompromise")
	test.Assert(t, bytes.Equal(digest[:], mockSA.added.KeyHash), "key hash mismatch")
	test.AssertEquals(t, mockSA.added.Source, "API")
	test.Assert(t, mockSA.added.Comment == "", "Comment is not empty")
	test.AssertEquals(t, test.CountCounterVec(
		"reason", "keyCompromise", ra.revocationReasonCounter), 1)

	mockSA.added = nil
	err = ra.AdministrativelyRevokeCertificate(context.Background(), *cert, ocsp.KeyCompromise, "root")
	test.AssertNotError(t, err, "AdministrativelyRevokeCertificate failed")
	test.Assert(t, mockSA.added != nil, "blocked key was not added when reason was keyCompromise")
	test.Assert(t, bytes.Equal(digest[:], mockSA.added.KeyHash), "key hash mismatch")
	test.AssertEquals(t, mockSA.added.Source, "admin-revoker")
	test.Assert(t, mockSA.added.Comment != "", "Comment is nil")
	test.AssertEquals(t, mockSA.added.Comment, "revoked by root")
	test.AssertEquals(t, test.CountCounterVec(
		"reason", "keyCompromise", ra.revocationReasonCounter), 2)
}
