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
	"errors"
	"fmt"
	"math/big"
	mrand "math/rand/v2"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	ctasn1 "github.com/google/certificate-transparency-go/asn1"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctpkix "github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	akamaipb "github.com/letsencrypt/boulder/akamai/proto"
	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/ctpolicy"
	"github.com/letsencrypt/boulder/ctpolicy/loglist"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/policy"
	pubpb "github.com/letsencrypt/boulder/publisher/proto"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/ratelimit"
	"github.com/letsencrypt/boulder/ratelimits"
	"github.com/letsencrypt/boulder/sa"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/test"
	isa "github.com/letsencrypt/boulder/test/inmem/sa"
	"github.com/letsencrypt/boulder/test/vars"
	"github.com/letsencrypt/boulder/va"
	vapb "github.com/letsencrypt/boulder/va/proto"
)

// randomDomain creates a random domain name for testing.
//
// panics if crypto/rand.Rand.Read fails.
func randomDomain() string {
	var bytes [4]byte
	_, err := rand.Read(bytes[:])
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x.example.com", bytes[:])
}

func createPendingAuthorization(t *testing.T, sa sapb.StorageAuthorityClient, domain string, exp time.Time) *corepb.Authorization {
	t.Helper()

	res, err := sa.NewOrderAndAuthzs(
		context.Background(),
		&sapb.NewOrderAndAuthzsRequest{
			NewOrder: &sapb.NewOrderRequest{
				RegistrationID: Registration.Id,
				Expires:        timestamppb.New(exp),
				DnsNames:       []string{domain},
			},
			NewAuthzs: []*sapb.NewAuthzRequest{
				{
					Identifier:     &corepb.Identifier{Type: string(core.ChallengeTypeDNS01), Value: domain},
					RegistrationID: Registration.Id,
					Expires:        timestamppb.New(exp),
					ChallengeTypes: []string{
						string(core.ChallengeTypeHTTP01),
						string(core.ChallengeTypeDNS01),
						string(core.ChallengeTypeTLSALPN01)},
					Token: core.NewToken(),
				},
			},
		},
	)
	test.AssertNotError(t, err, "sa.NewOrderAndAuthzs failed")

	return getAuthorization(t, fmt.Sprint(res.V2Authorizations[0]), sa)
}

func createFinalizedAuthorization(t *testing.T, sa sapb.StorageAuthorityClient, domain string, exp time.Time, chall core.AcmeChallenge, attemptedAt time.Time) int64 {
	t.Helper()
	pending := createPendingAuthorization(t, sa, domain, exp)
	pendingID, err := strconv.ParseInt(pending.Id, 10, 64)
	test.AssertNotError(t, err, "strconv.ParseInt failed")
	_, err = sa.FinalizeAuthorization2(context.Background(), &sapb.FinalizeAuthorizationRequest{
		Id:          pendingID,
		Status:      "valid",
		Expires:     timestamppb.New(exp),
		Attempted:   string(chall),
		AttemptedAt: timestamppb.New(attemptedAt),
	})
	test.AssertNotError(t, err, "sa.FinalizeAuthorizations2 failed")
	return pendingID
}

func getAuthorization(t *testing.T, id string, sa sapb.StorageAuthorityClient) *corepb.Authorization {
	t.Helper()
	idInt, err := strconv.ParseInt(id, 10, 64)
	test.AssertNotError(t, err, "strconv.ParseInt failed")
	dbAuthz, err := sa.GetAuthorization2(ctx, &sapb.AuthorizationID2{Id: idInt})
	test.AssertNotError(t, err, "Could not fetch authorization from database")
	return dbAuthz
}

func dnsChallIdx(t *testing.T, challenges []*corepb.Challenge) int64 {
	t.Helper()
	var challIdx int64
	var set bool
	for i, ch := range challenges {
		if core.AcmeChallenge(ch.Type) == core.ChallengeTypeDNS01 {
			challIdx = int64(i)
			set = true
			break
		}
	}
	if !set {
		t.Errorf("dnsChallIdx didn't find challenge of type DNS-01")
	}
	return challIdx
}

func numAuthorizations(o *corepb.Order) int {
	return len(o.V2Authorizations)
}

type DummyValidationAuthority struct {
	doDCVRequest chan *vapb.PerformValidationRequest
	doDCVError   error
	doDCVResult  *vapb.ValidationResult

	doCAARequest  chan *vapb.IsCAAValidRequest
	doCAAError    error
	doCAAResponse *vapb.IsCAAValidResponse
}

func (dva *DummyValidationAuthority) PerformValidation(ctx context.Context, req *vapb.PerformValidationRequest, _ ...grpc.CallOption) (*vapb.ValidationResult, error) {
	dcvRes, err := dva.DoDCV(ctx, req)
	if err != nil {
		return nil, err
	}
	if dcvRes.Problem != nil {
		return dcvRes, nil
	}
	caaResp, err := dva.DoCAA(ctx, &vapb.IsCAAValidRequest{
		Domain:           req.DnsName,
		ValidationMethod: req.Challenge.Type,
		AccountURIID:     req.Authz.RegID,
		AuthzID:          req.Authz.Id,
	})
	if err != nil {
		return nil, err
	}
	return &vapb.ValidationResult{
		Records: dcvRes.Records,
		Problem: caaResp.Problem,
	}, nil
}

func (dva *DummyValidationAuthority) IsCAAValid(ctx context.Context, req *vapb.IsCAAValidRequest, _ ...grpc.CallOption) (*vapb.IsCAAValidResponse, error) {
	return nil, status.Error(codes.Unimplemented, "IsCAAValid not implemented")
}

func (dva *DummyValidationAuthority) DoDCV(ctx context.Context, req *vapb.PerformValidationRequest, _ ...grpc.CallOption) (*vapb.ValidationResult, error) {
	dva.doDCVRequest <- req
	return dva.doDCVResult, dva.doDCVError
}

func (dva *DummyValidationAuthority) DoCAA(ctx context.Context, req *vapb.IsCAAValidRequest, _ ...grpc.CallOption) (*vapb.IsCAAValidResponse, error) {
	dva.doCAARequest <- req
	return dva.doCAAResponse, dva.doCAAError
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

	ResponseIndex = 0

	ExampleCSR = &x509.CertificateRequest{}

	Registration = &corepb.Registration{Id: 1}

	Identifier = "not-example.com"

	log = blog.UseMock()
)

var ctx = context.Background()

func newAcctKey(t *testing.T) []byte {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := &jose.JSONWebKey{Key: key.Public()}
	acctKey, err := jwk.MarshalJSON()
	test.AssertNotError(t, err, "failed to marshal account key")
	return acctKey
}

func initAuthorities(t *testing.T) (*DummyValidationAuthority, sapb.StorageAuthorityClient, *RegistrationAuthorityImpl, ratelimits.Source, clock.FakeClock, func()) {
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
	fc.Set(time.Date(2020, 3, 4, 5, 0, 0, 0, time.UTC))

	dbMap, err := sa.DBMapForTest(vars.DBConnSA)
	if err != nil {
		t.Fatalf("Failed to create dbMap: %s", err)
	}
	ssa, err := sa.NewSQLStorageAuthority(dbMap, dbMap, nil, 1, 0, fc, log, metrics.NoopRegisterer)
	if err != nil {
		t.Fatalf("Failed to create SA: %s", err)
	}
	sa := &isa.SA{Impl: ssa}

	saDBCleanUp := test.ResetBoulderTestDatabase(t)

	dummyVA := &DummyValidationAuthority{
		doDCVRequest: make(chan *vapb.PerformValidationRequest, 1),
		doCAARequest: make(chan *vapb.IsCAAValidRequest, 1),
	}
	va := va.RemoteClients{VAClient: dummyVA, CAAClient: dummyVA}

	pa, err := policy.New(map[core.AcmeChallenge]bool{
		core.ChallengeTypeHTTP01: true,
		core.ChallengeTypeDNS01:  true,
	}, blog.NewMock())
	test.AssertNotError(t, err, "Couldn't create PA")
	err = pa.LoadHostnamePolicyFile("../test/hostname-policy.yaml")
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

	test.AssertNotError(t, err, "Couldn't create initial IP")
	Registration, _ = ssa.NewRegistration(ctx, &corepb.Registration{
		Key:    AccountKeyJSONA,
		Status: string(core.StatusValid),
	})

	ctp := ctpolicy.New(&mocks.PublisherClient{}, loglist.List{
		"OperA": {
			"LogA1": {Url: "UrlA1", Key: "KeyA1"},
		},
		"OperB": {
			"LogB1": {Url: "UrlB1", Key: "KeyB1"},
		},
	}, nil, nil, 0, log, metrics.NoopRegisterer)

	rlSource := ratelimits.NewInmemSource()
	limiter, err := ratelimits.NewLimiter(fc, rlSource, stats)
	test.AssertNotError(t, err, "making limiter")
	txnBuilder, err := ratelimits.NewTransactionBuilderFromFiles("../test/config-next/wfe2-ratelimit-defaults.yml", "")
	test.AssertNotError(t, err, "making transaction composer")

	testKeyPolicy, err := goodkey.NewPolicy(nil, nil)
	test.AssertNotError(t, err, "making keypolicy")

	ra := NewRegistrationAuthorityImpl(
		fc, log, stats,
		1, testKeyPolicy, limiter, txnBuilder, 100,
		300*24*time.Hour, 7*24*time.Hour,
		nil,
		7*24*time.Hour, 5*time.Minute,
		ctp, nil, nil)
	ra.SA = sa
	ra.VA = va
	ra.CA = ca
	ra.OCSP = &mocks.MockOCSPGenerator{}
	ra.PA = pa
	return dummyVA, sa, ra, rlSource, fc, cleanUp
}

func TestValidateContacts(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	ansible := "ansible:earth.sol.milkyway.laniakea/letsencrypt"
	validEmail := "mailto:admin@email.com"
	otherValidEmail := "mailto:other-admin@email.com"
	malformedEmail := "mailto:admin.com"
	nonASCII := "mailto:señor@email.com"
	unparsable := "mailto:a@email.com, b@email.com"
	forbidden := "mailto:a@example.org"

	err := ra.validateContacts([]string{})
	test.AssertNotError(t, err, "No Contacts")

	err = ra.validateContacts([]string{validEmail, otherValidEmail})
	test.AssertError(t, err, "Too Many Contacts")

	err = ra.validateContacts([]string{validEmail})
	test.AssertNotError(t, err, "Valid Email")

	err = ra.validateContacts([]string{malformedEmail})
	test.AssertError(t, err, "Malformed Email")

	err = ra.validateContacts([]string{ansible})
	test.AssertError(t, err, "Unknown scheme")

	err = ra.validateContacts([]string{""})
	test.AssertError(t, err, "Empty URL")

	err = ra.validateContacts([]string{nonASCII})
	test.AssertError(t, err, "Non ASCII email")

	err = ra.validateContacts([]string{unparsable})
	test.AssertError(t, err, "Unparsable email")

	err = ra.validateContacts([]string{forbidden})
	test.AssertError(t, err, "Forbidden email")

	err = ra.validateContacts([]string{"mailto:admin@localhost"})
	test.AssertError(t, err, "Forbidden email")

	err = ra.validateContacts([]string{"mailto:admin@example.not.a.iana.suffix"})
	test.AssertError(t, err, "Forbidden email")

	err = ra.validateContacts([]string{"mailto:admin@1.2.3.4"})
	test.AssertError(t, err, "Forbidden email")

	err = ra.validateContacts([]string{"mailto:admin@[1.2.3.4]"})
	test.AssertError(t, err, "Forbidden email")

	err = ra.validateContacts([]string{"mailto:admin@a.com?no-reminder-emails"})
	test.AssertError(t, err, "No hfields in email")

	err = ra.validateContacts([]string{"mailto:example@a.com?"})
	test.AssertError(t, err, "No hfields in email")

	err = ra.validateContacts([]string{"mailto:example@a.com#"})
	test.AssertError(t, err, "No fragment")

	err = ra.validateContacts([]string{"mailto:example@a.com#optional"})
	test.AssertError(t, err, "No fragment")

	// The registrations.contact field is VARCHAR(191). 175 'a' characters plus
	// the prefix "mailto:" and the suffix "@a.com" makes exactly 191 bytes of
	// encoded JSON. The correct size to hit our maximum DB field length.
	var longStringBuf strings.Builder
	longStringBuf.WriteString("mailto:")
	for range 175 {
		longStringBuf.WriteRune('a')
	}
	longStringBuf.WriteString("@a.com")

	err = ra.validateContacts([]string{longStringBuf.String()})
	test.AssertError(t, err, "Too long contacts")
}

func TestNewRegistration(t *testing.T) {
	_, sa, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	mailto := "mailto:foo@letsencrypt.org"
	acctKeyB, err := AccountKeyB.MarshalJSON()
	test.AssertNotError(t, err, "failed to marshal account key")
	input := &corepb.Registration{
		Contact:         []string{mailto},
		ContactsPresent: true,
		Key:             acctKeyB,
	}

	result, err := ra.NewRegistration(ctx, input)
	if err != nil {
		t.Fatalf("could not create new registration: %s", err)
	}
	test.AssertByteEquals(t, result.Key, acctKeyB)
	test.Assert(t, len(result.Contact) == 1, "Wrong number of contacts")
	test.Assert(t, mailto == (result.Contact)[0], "Contact didn't match")
	test.Assert(t, result.Agreement == "", "Agreement didn't default empty")

	reg, err := sa.GetRegistration(ctx, &sapb.RegistrationID{Id: result.Id})
	test.AssertNotError(t, err, "Failed to retrieve registration")
	test.AssertByteEquals(t, reg.Key, acctKeyB)
}

func TestNewRegistrationContactsPresent(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	testCases := []struct {
		Name        string
		Reg         *corepb.Registration
		ExpectedErr error
	}{
		{
			Name: "No contacts provided by client ContactsPresent false",
			Reg: &corepb.Registration{
				Key: newAcctKey(t),
			},
			ExpectedErr: nil,
		},
		{
			Name: "Empty contact provided by client ContactsPresent true",
			Reg: &corepb.Registration{
				Contact:         []string{},
				ContactsPresent: true,
				Key:             newAcctKey(t),
			},
			ExpectedErr: nil,
		},
		{
			Name: "Valid contact provided by client ContactsPresent true",
			Reg: &corepb.Registration{
				Contact:         []string{"mailto:foo@letsencrypt.org"},
				ContactsPresent: true,
				Key:             newAcctKey(t),
			},
			ExpectedErr: nil,
		},
		{
			Name: "Valid contact provided by client ContactsPresent false",
			Reg: &corepb.Registration{
				Contact:         []string{"mailto:foo@letsencrypt.org"},
				ContactsPresent: false,
				Key:             newAcctKey(t),
			},
			ExpectedErr: fmt.Errorf("account contacts present but contactsPresent false"),
		},
	}
	// For each test case we check that the NewRegistration works as
	// intended with variations of Contact and ContactsPresent fields
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Create new registration
			_, err := ra.NewRegistration(ctx, tc.Reg)
			// Check error output
			if tc.ExpectedErr == nil {
				test.AssertNotError(t, err, "expected no error for NewRegistration")
			} else {
				test.AssertError(t, err, "expected error for NewRegistration")
				test.AssertEquals(t, err.Error(), tc.ExpectedErr.Error())
			}
		})
	}
}

type mockSAFailsNewRegistration struct {
	sapb.StorageAuthorityClient
}

func (sa *mockSAFailsNewRegistration) NewRegistration(_ context.Context, _ *corepb.Registration, _ ...grpc.CallOption) (*corepb.Registration, error) {
	return &corepb.Registration{}, fmt.Errorf("too bad")
}

func TestNewRegistrationSAFailure(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.SA = &mockSAFailsNewRegistration{}
	acctKeyB, err := AccountKeyB.MarshalJSON()
	test.AssertNotError(t, err, "failed to marshal account key")
	input := corepb.Registration{
		Contact:         []string{"mailto:test@example.com"},
		ContactsPresent: true,
		Key:             acctKeyB,
	}
	result, err := ra.NewRegistration(ctx, &input)
	if err == nil {
		t.Fatalf("NewRegistration should have failed when SA.NewRegistration failed %#v", result.Key)
	}
}

func TestNewRegistrationNoFieldOverwrite(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	mailto := "mailto:foo@letsencrypt.org"
	acctKeyC, err := AccountKeyC.MarshalJSON()
	test.AssertNotError(t, err, "failed to marshal account key")
	input := &corepb.Registration{
		Id:              23,
		Key:             acctKeyC,
		Contact:         []string{mailto},
		ContactsPresent: true,
		Agreement:       "I agreed",
	}

	result, err := ra.NewRegistration(ctx, input)
	test.AssertNotError(t, err, "Could not create new registration")
	test.Assert(t, result.Id != 23, "ID shouldn't be set by user")
	// TODO: Enable this test case once we validate terms agreement.
	//test.Assert(t, result.Agreement != "I agreed", "Agreement shouldn't be set with invalid URL")
}

func TestNewRegistrationBadKey(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	mailto := "mailto:foo@letsencrypt.org"
	shortKey, err := ShortKey.MarshalJSON()
	test.AssertNotError(t, err, "failed to marshal account key")
	input := &corepb.Registration{
		Contact:         []string{mailto},
		ContactsPresent: true,
		Key:             shortKey,
	}
	_, err = ra.NewRegistration(ctx, input)
	test.AssertError(t, err, "Should have rejected authorization with short key")
}

type NoUpdateSA struct {
	sapb.StorageAuthorityClient
}

// Deprecated: When this function is removed, the NoUpdateSA should be moved
// down to join the other mocks and tests for UpdateRegistrationContact & Key,
// where it's also used.
func (sa *NoUpdateSA) UpdateRegistration(_ context.Context, _ *corepb.Registration, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return nil, fmt.Errorf("UpdateRegistration() is mocked to always error")
}

func (sa *NoUpdateSA) UpdateRegistrationContact(_ context.Context, _ *sapb.UpdateRegistrationContactRequest, _ ...grpc.CallOption) (*corepb.Registration, error) {
	return nil, fmt.Errorf("UpdateRegistrationContact() is mocked to always error")
}

func (sa *NoUpdateSA) UpdateRegistrationKey(_ context.Context, _ *sapb.UpdateRegistrationKeyRequest, _ ...grpc.CallOption) (*corepb.Registration, error) {
	return nil, fmt.Errorf("UpdateRegistrationKey() is mocked to always error")
}

func TestUpdateRegistrationSame(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	mailto := "mailto:foo@letsencrypt.org"

	// Make a new registration with AccountKeyC and a Contact
	acctKeyC, err := AccountKeyC.MarshalJSON()
	test.AssertNotError(t, err, "failed to marshal account key")
	reg := &corepb.Registration{
		Key:             acctKeyC,
		Contact:         []string{mailto},
		ContactsPresent: true,
		Agreement:       "I agreed",
	}
	result, err := ra.NewRegistration(ctx, reg)
	test.AssertNotError(t, err, "Could not create new registration")

	// Switch to a mock SA that will always error if UpdateRegistration() is called
	ra.SA = &NoUpdateSA{}

	// Make an update to the registration with the same Contact & Agreement values.
	updateSame := &corepb.Registration{
		Id:              result.Id,
		Key:             acctKeyC,
		Contact:         []string{mailto},
		ContactsPresent: true,
		Agreement:       "I agreed",
	}

	// The update operation should *not* error, even with the NoUpdateSA because
	// UpdateRegistration() should not be called when the update content doesn't
	// actually differ from the existing content
	_, err = ra.UpdateRegistration(ctx, &rapb.UpdateRegistrationRequest{Base: result, Update: updateSame})
	test.AssertNotError(t, err, "Error updating registration")
}

func TestPerformValidationExpired(t *testing.T) {
	_, sa, ra, _, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	authz := createPendingAuthorization(t, sa, Identifier, fc.Now().Add(-2*time.Hour))

	_, err := ra.PerformValidation(ctx, &rapb.PerformValidationRequest{
		Authz:          authz,
		ChallengeIndex: int64(ResponseIndex),
	})
	test.AssertError(t, err, "Updated expired authorization")
}

func TestPerformValidationAlreadyValid(t *testing.T) {
	va, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Create a finalized authorization
	exp := ra.clk.Now().Add(365 * 24 * time.Hour)
	authz := core.Authorization{
		ID:             "1337",
		Identifier:     identifier.NewDNS("not-example.com"),
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

	va.doDCVResult = &vapb.ValidationResult{
		Records: []*corepb.ValidationRecord{
			{
				AddressUsed: []byte("192.168.0.1"),
				Hostname:    "example.com",
				Port:        "8080",
				Url:         "http://example.com/",
			},
		},
		Problem: nil,
	}
	va.doCAAResponse = &vapb.IsCAAValidResponse{Problem: nil}

	// A subsequent call to perform validation should return nil due
	// to being short-circuited because of valid authz reuse.
	val, err := ra.PerformValidation(ctx, &rapb.PerformValidationRequest{
		Authz:          authzPB,
		ChallengeIndex: int64(ResponseIndex),
	})
	test.Assert(t, core.AcmeStatus(val.Status) == core.StatusValid, "Validation should have been valid")
	test.AssertNotError(t, err, "Error was not nil, but should have been nil")
}

func TestPerformValidationSuccess(t *testing.T) {
	va, sa, ra, _, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	// We know this is OK because of TestNewAuthorization
	authzPB := createPendingAuthorization(t, sa, Identifier, fc.Now().Add(12*time.Hour))

	va.doDCVResult = &vapb.ValidationResult{
		Records: []*corepb.ValidationRecord{
			{
				AddressUsed:   []byte("192.168.0.1"),
				Hostname:      "example.com",
				Port:          "8080",
				Url:           "http://example.com/",
				ResolverAddrs: []string{"rebound"},
			},
		},
		Problem: nil,
	}
	va.doCAAResponse = &vapb.IsCAAValidResponse{Problem: nil}

	now := fc.Now()
	challIdx := dnsChallIdx(t, authzPB.Challenges)
	authzPB, err := ra.PerformValidation(ctx, &rapb.PerformValidationRequest{
		Authz:          authzPB,
		ChallengeIndex: challIdx,
	})
	test.AssertNotError(t, err, "PerformValidation failed")

	var vaRequest *vapb.PerformValidationRequest
	select {
	case r := <-va.doDCVRequest:
		vaRequest = r
	case <-time.After(time.Second):
		t.Fatal("Timed out waiting for DummyValidationAuthority.PerformValidation to complete")
	}

	// Verify that the VA got the request, and it's the same as the others
	test.AssertEquals(t, authzPB.Challenges[challIdx].Type, vaRequest.Challenge.Type)
	test.AssertEquals(t, authzPB.Challenges[challIdx].Token, vaRequest.Challenge.Token)

	// Sleep so the RA has a chance to write to the SA
	time.Sleep(100 * time.Millisecond)

	dbAuthzPB := getAuthorization(t, authzPB.Id, sa)
	t.Log("dbAuthz:", dbAuthzPB)

	// Verify that the responses are reflected
	challIdx = dnsChallIdx(t, dbAuthzPB.Challenges)
	challenge, err := bgrpc.PBToChallenge(dbAuthzPB.Challenges[challIdx])
	test.AssertNotError(t, err, "Failed to marshall corepb.Challenge to core.Challenge.")

	test.AssertNotNil(t, vaRequest.Challenge, "Request passed to VA has no challenge")
	test.Assert(t, challenge.Status == core.StatusValid, "challenge was not marked as valid")

	// The DB authz's expiry should be equal to the current time plus the
	// configured authorization lifetime
	test.AssertEquals(t, dbAuthzPB.Expires.AsTime(), now.Add(ra.authorizationLifetime))

	// Check that validated timestamp was recorded, stored, and retrieved
	expectedValidated := fc.Now()
	test.Assert(t, *challenge.Validated == expectedValidated, "Validated timestamp incorrect or missing")
}

// mockSAWithSyncPause is a mock sapb.StorageAuthorityClient that forwards all
// method calls to an inner SA, but also performs a blocking write to a channel
// when PauseIdentifiers is called to allow the tests to synchronize.
type mockSAWithSyncPause struct {
	sapb.StorageAuthorityClient
	out chan<- *sapb.PauseRequest
}

func (msa mockSAWithSyncPause) PauseIdentifiers(ctx context.Context, req *sapb.PauseRequest, _ ...grpc.CallOption) (*sapb.PauseIdentifiersResponse, error) {
	res, err := msa.StorageAuthorityClient.PauseIdentifiers(ctx, req)
	msa.out <- req
	return res, err
}

func TestPerformValidation_FailedValidationsTriggerPauseIdentifiersRatelimit(t *testing.T) {
	va, sa, ra, rl, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	features.Set(features.Config{AutomaticallyPauseZombieClients: true})
	defer features.Reset()

	// Replace the SA with one that will block when PauseIdentifiers is called.
	pauseChan := make(chan *sapb.PauseRequest)
	defer close(pauseChan)
	ra.SA = mockSAWithSyncPause{
		StorageAuthorityClient: ra.SA,
		out:                    pauseChan,
	}

	// Override the default ratelimits to only allow one failed validation per
	// 24 hours before pausing.
	txnBuilder, err := ratelimits.NewTransactionBuilder(ratelimits.LimitConfigs{
		ratelimits.FailedAuthorizationsForPausingPerDomainPerAccount.String(): &ratelimits.LimitConfig{
			Burst:  1,
			Count:  1,
			Period: config.Duration{Duration: time.Hour * 24}},
	})
	test.AssertNotError(t, err, "making transaction composer")
	ra.txnBuilder = txnBuilder

	// Set up a fake domain, authz, and bucket key to care about.
	domain := randomDomain()
	authzPB := createPendingAuthorization(t, sa, domain, fc.Now().Add(12*time.Hour))
	bucketKey, err := ratelimits.NewRegIdDomainBucketKey(ratelimits.FailedAuthorizationsForPausingPerDomainPerAccount, authzPB.RegistrationID, domain)
	test.AssertNotError(t, err, "constructing test bucket key")

	// Set the stored TAT to indicate that this bucket has exhausted its quota.
	err = rl.BatchSet(context.Background(), map[string]time.Time{
		bucketKey: fc.Now().Add(25 * time.Hour),
	})
	test.AssertNotError(t, err, "updating rate limit bucket")

	// Now a failed validation should result in the identifier being paused
	// due to the strict ratelimit.
	va.doDCVResult = &vapb.ValidationResult{
		Records: []*corepb.ValidationRecord{
			{
				AddressUsed:   []byte("192.168.0.1"),
				Hostname:      domain,
				Port:          "8080",
				Url:           fmt.Sprintf("http://%s/", domain),
				ResolverAddrs: []string{"rebound"},
			},
		},
		Problem: nil,
	}
	va.doCAAResponse = &vapb.IsCAAValidResponse{
		Problem: &corepb.ProblemDetails{
			Detail: fmt.Sprintf("CAA invalid for %s", domain),
		},
	}

	_, err = ra.PerformValidation(ctx, &rapb.PerformValidationRequest{
		Authz:          authzPB,
		ChallengeIndex: dnsChallIdx(t, authzPB.Challenges),
	})
	test.AssertNotError(t, err, "PerformValidation failed")

	// Wait for the RA to finish processing the validation, and ensure that the paused
	// account+identifier is what we expect.
	paused := <-pauseChan
	test.AssertEquals(t, len(paused.Identifiers), 1)
	test.AssertEquals(t, paused.Identifiers[0].Value, domain)
}

// mockRLSourceWithSyncDelete is a mock ratelimits.Source that forwards all
// method calls to an inner Source, but also performs a blocking write to a
// channel when Delete is called to allow the tests to synchronize.
type mockRLSourceWithSyncDelete struct {
	ratelimits.Source
	out chan<- string
}

func (rl mockRLSourceWithSyncDelete) Delete(ctx context.Context, bucketKey string) error {
	err := rl.Source.Delete(ctx, bucketKey)
	rl.out <- bucketKey
	return err
}

func TestPerformValidation_FailedThenSuccessfulValidationResetsPauseIdentifiersRatelimit(t *testing.T) {
	va, sa, ra, rl, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	features.Set(features.Config{AutomaticallyPauseZombieClients: true})
	defer features.Reset()

	// Replace the rate limit source with one that will block when Delete is called.
	keyChan := make(chan string)
	defer close(keyChan)
	limiter, err := ratelimits.NewLimiter(fc, mockRLSourceWithSyncDelete{
		Source: rl,
		out:    keyChan,
	}, metrics.NoopRegisterer)
	test.AssertNotError(t, err, "creating mock limiter")
	ra.limiter = limiter

	// Set up a fake domain, authz, and bucket key to care about.
	domain := randomDomain()
	authzPB := createPendingAuthorization(t, sa, domain, fc.Now().Add(12*time.Hour))
	bucketKey, err := ratelimits.NewRegIdDomainBucketKey(ratelimits.FailedAuthorizationsForPausingPerDomainPerAccount, authzPB.RegistrationID, domain)
	test.AssertNotError(t, err, "constructing test bucket key")

	// Set a stored TAT so that we can tell when it's been reset.
	err = rl.BatchSet(context.Background(), map[string]time.Time{
		bucketKey: fc.Now().Add(25 * time.Hour),
	})
	test.AssertNotError(t, err, "updating rate limit bucket")

	va.doDCVResult = &vapb.ValidationResult{
		Records: []*corepb.ValidationRecord{
			{
				AddressUsed:   []byte("192.168.0.1"),
				Hostname:      domain,
				Port:          "8080",
				Url:           fmt.Sprintf("http://%s/", domain),
				ResolverAddrs: []string{"rebound"},
			},
		},
		Problem: nil,
	}
	va.doCAAResponse = &vapb.IsCAAValidResponse{Problem: nil}

	_, err = ra.PerformValidation(ctx, &rapb.PerformValidationRequest{
		Authz:          authzPB,
		ChallengeIndex: dnsChallIdx(t, authzPB.Challenges),
	})
	test.AssertNotError(t, err, "PerformValidation failed")

	// Wait for the RA to finish processesing the validation, and ensure that
	// the reset bucket key is what we expect.
	reset := <-keyChan
	test.AssertEquals(t, reset, bucketKey)

	// Verify that the bucket no longer exists (because the limiter reset has
	// deleted it). This indicates the accountID:identifier bucket has regained
	// capacity avoiding being inadvertently paused.
	_, err = rl.Get(ctx, bucketKey)
	test.AssertErrorIs(t, err, ratelimits.ErrBucketNotFound)
}

func TestPerformValidationVAError(t *testing.T) {
	va, sa, ra, _, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	authzPB := createPendingAuthorization(t, sa, Identifier, fc.Now().Add(12*time.Hour))

	va.doDCVError = fmt.Errorf("Something went wrong")

	challIdx := dnsChallIdx(t, authzPB.Challenges)
	authzPB, err := ra.PerformValidation(ctx, &rapb.PerformValidationRequest{
		Authz:          authzPB,
		ChallengeIndex: challIdx,
	})

	test.AssertNotError(t, err, "PerformValidation completely failed")

	var vaRequest *vapb.PerformValidationRequest
	select {
	case r := <-va.doDCVRequest:
		vaRequest = r
	case <-time.After(time.Second):
		t.Fatal("Timed out waiting for DummyValidationAuthority.PerformValidation to complete")
	}

	// Verify that the VA got the request, and it's the same as the others
	test.AssertEquals(t, authzPB.Challenges[challIdx].Type, vaRequest.Challenge.Type)
	test.AssertEquals(t, authzPB.Challenges[challIdx].Token, vaRequest.Challenge.Token)

	// Sleep so the RA has a chance to write to the SA
	time.Sleep(100 * time.Millisecond)

	dbAuthzPB := getAuthorization(t, authzPB.Id, sa)
	t.Log("dbAuthz:", dbAuthzPB)

	// Verify that the responses are reflected
	challIdx = dnsChallIdx(t, dbAuthzPB.Challenges)
	challenge, err := bgrpc.PBToChallenge(dbAuthzPB.Challenges[challIdx])
	test.AssertNotError(t, err, "Failed to marshall corepb.Challenge to core.Challenge.")
	test.Assert(t, challenge.Status == core.StatusInvalid, "challenge was not marked as invalid")
	test.AssertContains(t, challenge.Error.Error(), "Could not communicate with VA")
	test.Assert(t, challenge.ValidationRecord == nil, "challenge had a ValidationRecord")

	// Check that validated timestamp was recorded, stored, and retrieved
	expectedValidated := fc.Now()
	test.Assert(t, *challenge.Validated == expectedValidated, "Validated timestamp incorrect or missing")
}

func TestCertificateKeyNotEqualAccountKey(t *testing.T) {
	_, sa, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	exp := ra.clk.Now().Add(365 * 24 * time.Hour)

	authzID := createFinalizedAuthorization(t, sa, "www.example.com", exp, core.ChallengeTypeHTTP01, ra.clk.Now())

	order, err := sa.NewOrderAndAuthzs(context.Background(), &sapb.NewOrderAndAuthzsRequest{
		NewOrder: &sapb.NewOrderRequest{
			RegistrationID:   Registration.Id,
			Expires:          timestamppb.New(exp),
			DnsNames:         []string{"www.example.com"},
			V2Authorizations: []int64{authzID},
		},
	})
	test.AssertNotError(t, err, "Could not add test order with finalized authz IDs, ready status")

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		// Registration has key == AccountKeyA
		PublicKey:          AccountKeyA.Key,
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           []string{"www.example.com"},
	}, AccountPrivateKey.Key)
	test.AssertNotError(t, err, "Failed to sign CSR")

	_, err = ra.FinalizeOrder(ctx, &rapb.FinalizeOrderRequest{
		Order: &corepb.Order{
			Status:         string(core.StatusReady),
			DnsNames:       []string{"www.example.com"},
			Id:             order.Id,
			RegistrationID: Registration.Id,
		},
		Csr: csrBytes,
	})
	test.AssertError(t, err, "Should have rejected cert with key = account key")
	test.AssertEquals(t, err.Error(), "certificate public key must be different than account key")
}

// mockInvalidAuthorizationsAuthority is a mock which claims that the given
// domain has one invalid authorization.
type mockInvalidAuthorizationsAuthority struct {
	sapb.StorageAuthorityClient
	domainWithFailures string
}

func (sa *mockInvalidAuthorizationsAuthority) CountInvalidAuthorizations2(ctx context.Context, req *sapb.CountInvalidAuthorizationsRequest, _ ...grpc.CallOption) (*sapb.Count, error) {
	if req.DnsName == sa.domainWithFailures {
		return &sapb.Count{Count: 1}, nil
	} else {
		return &sapb.Count{}, nil
	}
}

func TestAuthzFailedRateLimitingNewOrder(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	txnBuilder, err := ratelimits.NewTransactionBuilder(ratelimits.LimitConfigs{
		ratelimits.FailedAuthorizationsForPausingPerDomainPerAccount.String(): &ratelimits.LimitConfig{
			Burst:  1,
			Count:  1,
			Period: config.Duration{Duration: time.Hour * 1}},
	})
	test.AssertNotError(t, err, "making transaction composer")
	ra.txnBuilder = txnBuilder

	limit := ra.rlPolicies.InvalidAuthorizationsPerAccount()
	ra.SA = &mockInvalidAuthorizationsAuthority{domainWithFailures: "all.i.do.is.lose.com"}
	err = ra.checkInvalidAuthorizationLimits(ctx, Registration.Id,
		[]string{"charlie.brown.com", "all.i.do.is.lose.com"}, limit)
	test.AssertError(t, err, "checkInvalidAuthorizationLimits did not encounter expected rate limit error")
	test.AssertEquals(t, err.Error(), "too many failed authorizations recently: see https://letsencrypt.org/docs/rate-limits/#authorization-failures-per-hostname-per-account")
}

type mockSAWithNameCounts struct {
	sapb.StorageAuthorityClient
	nameCounts *sapb.CountByNames
	t          *testing.T
	clk        clock.FakeClock
}

func (m *mockSAWithNameCounts) CountCertificatesByNames(ctx context.Context, req *sapb.CountCertificatesByNamesRequest, _ ...grpc.CallOption) (*sapb.CountByNames, error) {
	expectedLatest := m.clk.Now()
	if req.Range.Latest.AsTime() != expectedLatest {
		m.t.Errorf("incorrect latest: got '%v', expected '%v'", req.Range.Latest.AsTime(), expectedLatest)
	}
	expectedEarliest := m.clk.Now().Add(-23 * time.Hour)
	if req.Range.Earliest.AsTime() != expectedEarliest {
		m.t.Errorf("incorrect earliest: got '%v', expected '%v'", req.Range.Earliest.AsTime(), expectedEarliest)
	}
	counts := make(map[string]int64)
	for _, name := range req.DnsNames {
		if count, ok := m.nameCounts.Counts[name]; ok {
			counts[name] = count
		}
	}
	return &sapb.CountByNames{Counts: counts}, nil
}

// FQDNSetExists is a mock which always returns false, so the test requests
// aren't considered to be renewals.
func (m *mockSAWithNameCounts) FQDNSetExists(ctx context.Context, req *sapb.FQDNSetExistsRequest, _ ...grpc.CallOption) (*sapb.Exists, error) {
	return &sapb.Exists{Exists: false}, nil
}

func TestCheckCertificatesPerNameLimit(t *testing.T) {
	_, _, ra, _, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	rlp := ratelimit.RateLimitPolicy{
		Threshold: 3,
		Window:    config.Duration{Duration: 23 * time.Hour},
		Overrides: map[string]int64{
			"bigissuer.com":     100,
			"smallissuer.co.uk": 1,
		},
	}

	mockSA := &mockSAWithNameCounts{
		nameCounts: &sapb.CountByNames{Counts: map[string]int64{"example.com": 1}},
		clk:        fc,
		t:          t,
	}

	ra.SA = mockSA

	// One base domain, below threshold
	err := ra.checkCertificatesPerNameLimit(ctx, []string{"www.example.com", "example.com"}, rlp, 99)
	test.AssertNotError(t, err, "rate limited example.com incorrectly")

	// Two base domains, one above threshold, one below
	mockSA.nameCounts.Counts["example.com"] = 10
	mockSA.nameCounts.Counts["good-example.com"] = 1
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"www.example.com", "example.com", "good-example.com"}, rlp, 99)
	test.AssertError(t, err, "incorrectly failed to rate limit example.com")
	test.AssertErrorIs(t, err, berrors.RateLimit)
	// There are no overrides for "example.com", so the override usage gauge
	// should contain 0 entries with labels matching it.
	test.AssertMetricWithLabelsEquals(t, ra.rlOverrideUsageGauge, prometheus.Labels{"limit": ratelimit.CertificatesPerName, "override_key": "example.com"}, 0)
	// Verify it has no sub errors as there is only one bad name
	test.AssertEquals(t, err.Error(), "too many certificates already issued for \"example.com\". Retry after 1970-01-01T23:00:00Z: see https://letsencrypt.org/docs/rate-limits/#new-orders-per-account")
	var bErr *berrors.BoulderError
	test.AssertErrorWraps(t, err, &bErr)
	test.AssertEquals(t, len(bErr.SubErrors), 0)

	// Three base domains, two above threshold, one below
	mockSA.nameCounts.Counts["example.com"] = 10
	mockSA.nameCounts.Counts["other-example.com"] = 10
	mockSA.nameCounts.Counts["good-example.com"] = 1
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"example.com", "other-example.com", "good-example.com"}, rlp, 99)
	test.AssertError(t, err, "incorrectly failed to rate limit example.com, other-example.com")
	test.AssertErrorIs(t, err, berrors.RateLimit)
	// Verify it has two sub errors as there are two bad names
	test.AssertEquals(t, err.Error(), "too many certificates already issued for multiple names (\"example.com\" and 2 others). Retry after 1970-01-01T23:00:00Z: see https://letsencrypt.org/docs/rate-limits/#new-orders-per-account")
	test.AssertErrorWraps(t, err, &bErr)
	test.AssertEquals(t, len(bErr.SubErrors), 2)

	// SA misbehaved and didn't send back a count for every input name
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"zombo.com", "www.example.com", "example.com"}, rlp, 99)
	test.AssertError(t, err, "incorrectly failed to error on misbehaving SA")

	// Two base domains, one above threshold but with an override.
	mockSA.nameCounts.Counts["example.com"] = 0
	mockSA.nameCounts.Counts["bigissuer.com"] = 50
	ra.rlOverrideUsageGauge.WithLabelValues(ratelimit.CertificatesPerName, "bigissuer.com").Set(.5)
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"www.example.com", "subdomain.bigissuer.com"}, rlp, 99)
	test.AssertNotError(t, err, "incorrectly rate limited bigissuer")
	// "bigissuer.com" has an override of 100 and they've issued 50. Accounting
	// for the anticipated issuance, we expect to see 51% utilization.
	test.AssertMetricWithLabelsEquals(t, ra.rlOverrideUsageGauge, prometheus.Labels{"limit": ratelimit.CertificatesPerName, "override_key": "bigissuer.com"}, .51)

	// Two base domains, one above its override
	mockSA.nameCounts.Counts["example.com"] = 10
	mockSA.nameCounts.Counts["bigissuer.com"] = 100
	ra.rlOverrideUsageGauge.WithLabelValues(ratelimit.CertificatesPerName, "bigissuer.com").Set(1)
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"www.example.com", "subdomain.bigissuer.com"}, rlp, 99)
	test.AssertError(t, err, "incorrectly failed to rate limit bigissuer")
	test.AssertErrorIs(t, err, berrors.RateLimit)
	// "bigissuer.com" has an override of 100 and they've issued 100. They're
	// already at 100% utilization, so we expect to see 100% utilization.
	test.AssertMetricWithLabelsEquals(t, ra.rlOverrideUsageGauge, prometheus.Labels{"limit": ratelimit.CertificatesPerName, "override_key": "bigissuer.com"}, 1)

	// One base domain, above its override (which is below threshold)
	mockSA.nameCounts.Counts["smallissuer.co.uk"] = 1
	ra.rlOverrideUsageGauge.WithLabelValues(ratelimit.CertificatesPerName, "smallissuer.co.uk").Set(1)
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"www.smallissuer.co.uk"}, rlp, 99)
	test.AssertError(t, err, "incorrectly failed to rate limit smallissuer")
	test.AssertErrorIs(t, err, berrors.RateLimit)
	// "smallissuer.co.uk" has an override of 1 and they've issued 1. They're
	// already at 100% utilization, so we expect to see 100% utilization.
	test.AssertMetricWithLabelsEquals(t, ra.rlOverrideUsageGauge, prometheus.Labels{"limit": ratelimit.CertificatesPerName, "override_key": "smallissuer.co.uk"}, 1)
}

// TestCheckExactCertificateLimit tests that the duplicate certificate limit
// applied to FQDN sets is respected.
func TestCheckExactCertificateLimit(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Create a rate limit with a small threshold
	const dupeCertLimit = 3
	rlp := ratelimit.RateLimitPolicy{
		Threshold: dupeCertLimit,
		Window:    config.Duration{Duration: 24 * time.Hour},
	}

	// Create a mock SA that has a count of already issued certificates for some
	// test names
	firstIssuanceTimestamp := ra.clk.Now().Add(-rlp.Window.Duration)
	fITS2 := firstIssuanceTimestamp.Add(time.Hour * 23)
	fITS3 := firstIssuanceTimestamp.Add(time.Hour * 16)
	fITS4 := firstIssuanceTimestamp.Add(time.Hour * 8)
	issuanceTimestampsNS := []int64{
		fITS2.UnixNano(),
		fITS3.UnixNano(),
		fITS4.UnixNano(),
		firstIssuanceTimestamp.UnixNano(),
	}
	issuanceTimestamps := []*timestamppb.Timestamp{
		timestamppb.New(fITS2),
		timestamppb.New(fITS3),
		timestamppb.New(fITS4),
		timestamppb.New(firstIssuanceTimestamp),
	}
	// Our window is 24 hours and our threshold is 3 issuance. If our most
	// recent issuance was 1 hour ago, we expect the next token to be available
	// 8 hours from issuance time or 7 hours from now.
	expectRetryAfterNS := time.Unix(0, issuanceTimestampsNS[0]).Add(time.Hour * 8).Format(time.RFC3339)
	expectRetryAfter := issuanceTimestamps[0].AsTime().Add(time.Hour * 8).Format(time.RFC3339)
	test.AssertEquals(t, expectRetryAfterNS, expectRetryAfter)
	ra.SA = &mockSAWithFQDNSet{
		issuanceTimestamps: map[string]*sapb.Timestamps{
			"none.example.com":          {Timestamps: []*timestamppb.Timestamp{}},
			"under.example.com":         {Timestamps: issuanceTimestamps[3:3]},
			"equalbutvalid.example.com": {Timestamps: issuanceTimestamps[1:3]},
			"over.example.com":          {Timestamps: issuanceTimestamps[0:3]},
		},
		t: t,
	}

	testCases := []struct {
		Name        string
		Domain      string
		ExpectedErr error
	}{
		{
			Name:        "FQDN set issuances none",
			Domain:      "none.example.com",
			ExpectedErr: nil,
		},
		{
			Name:        "FQDN set issuances less than limit",
			Domain:      "under.example.com",
			ExpectedErr: nil,
		},
		{
			Name:        "FQDN set issuances equal to limit",
			Domain:      "equalbutvalid.example.com",
			ExpectedErr: nil,
		},
		{
			Name:   "FQDN set issuances above limit NS",
			Domain: "over.example.com",
			ExpectedErr: fmt.Errorf(
				"too many certificates (3) already issued for this exact set of domains in the last 24 hours: over.example.com, retry after %s: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-hostnames",
				expectRetryAfterNS,
			),
		},
		{
			Name:   "FQDN set issuances above limit",
			Domain: "over.example.com",
			ExpectedErr: fmt.Errorf(
				"too many certificates (3) already issued for this exact set of domains in the last 24 hours: over.example.com, retry after %s: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-hostnames",
				expectRetryAfter,
			),
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
	base := &corepb.Registration{
		Id:        1,
		Contact:   []string{oldURL},
		Agreement: "",
	}
	update := &corepb.Registration{
		Contact:         []string{newURL},
		ContactsPresent: true,
		Agreement:       "totally!",
	}

	res, changed := mergeUpdate(base, update)
	test.AssertEquals(t, changed, true)
	test.AssertEquals(t, res.Contact[0], update.Contact[0])
	test.AssertEquals(t, res.Agreement, update.Agreement)

	// Make sure that a `MergeUpdate` call with an empty string doesn't produce an
	// error and results in a change to the base reg.
	emptyUpdate := &corepb.Registration{
		Contact:         []string{""},
		ContactsPresent: true,
		Agreement:       "totally!",
	}
	_, changed = mergeUpdate(res, emptyUpdate)
	test.AssertEquals(t, changed, true)
}

func TestRegistrationContactUpdate(t *testing.T) {
	contactURL := "mailto://example@example.com"

	// Test that a registration contact can be removed by updating with an empty
	// Contact slice.
	base := &corepb.Registration{
		Id:        1,
		Contact:   []string{contactURL},
		Agreement: "totally!",
	}
	update := &corepb.Registration{
		Id:              1,
		Contact:         []string{},
		ContactsPresent: true,
		Agreement:       "totally!",
	}
	res, changed := mergeUpdate(base, update)
	test.AssertEquals(t, changed, true)
	test.Assert(t, len(res.Contact) == 0, "Contact was not deleted in update")

	// Test that a registration contact isn't changed when an update is performed
	// with no Contact field
	base = &corepb.Registration{
		Id:        1,
		Contact:   []string{contactURL},
		Agreement: "totally!",
	}
	update = &corepb.Registration{
		Id:        1,
		Agreement: "totally!",
	}
	res, changed = mergeUpdate(base, update)
	test.AssertEquals(t, changed, false)
	test.Assert(t, len(res.Contact) == 1, "len(Contact) was updated unexpectedly")
	test.Assert(t, (res.Contact)[0] == contactURL, "Contact was changed unexpectedly")
}

func TestRegistrationKeyUpdate(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 512)
	test.AssertNotError(t, err, "rsa.GenerateKey() for oldKey failed")
	oldKeyJSON, err := jose.JSONWebKey{Key: oldKey}.MarshalJSON()
	test.AssertNotError(t, err, "MarshalJSON for oldKey failed")

	base := &corepb.Registration{Key: oldKeyJSON}
	update := &corepb.Registration{}
	_, changed := mergeUpdate(base, update)
	test.Assert(t, !changed, "mergeUpdate changed the key with empty update")

	newKey, err := rsa.GenerateKey(rand.Reader, 1024)
	test.AssertNotError(t, err, "rsa.GenerateKey() for newKey failed")
	newKeyJSON, err := jose.JSONWebKey{Key: newKey}.MarshalJSON()
	test.AssertNotError(t, err, "MarshalJSON for newKey failed")

	update = &corepb.Registration{Key: newKeyJSON}
	res, changed := mergeUpdate(base, update)
	test.Assert(t, changed, "mergeUpdate didn't change the key with non-empty update")
	test.AssertByteEquals(t, res.Key, update.Key)
}

// A mockSAWithFQDNSet is a mock StorageAuthority that supports
// CountCertificatesByName as well as FQDNSetExists. This allows testing
// checkCertificatesPerNameRateLimit's FQDN exemption logic.
type mockSAWithFQDNSet struct {
	sapb.StorageAuthorityClient
	fqdnSet            map[string]bool
	issuanceTimestamps map[string]*sapb.Timestamps

	t *testing.T
}

// Construct the FQDN Set key the same way as the SA (by using
// `core.UniqueLowerNames`, joining the names with a `,` and hashing them)
// but return a string so it can be used as a key in m.fqdnSet.
func (m mockSAWithFQDNSet) hashNames(names []string) string {
	names = core.UniqueLowerNames(names)
	hash := sha256.Sum256([]byte(strings.Join(names, ",")))
	return string(hash[:])
}

// Search for a set of domain names in the FQDN set map
func (m mockSAWithFQDNSet) FQDNSetExists(_ context.Context, req *sapb.FQDNSetExistsRequest, _ ...grpc.CallOption) (*sapb.Exists, error) {
	hash := m.hashNames(req.DnsNames)
	if _, exists := m.fqdnSet[hash]; exists {
		return &sapb.Exists{Exists: true}, nil
	}
	return &sapb.Exists{Exists: false}, nil
}

// Return a map of domain -> certificate count.
func (m mockSAWithFQDNSet) CountCertificatesByNames(ctx context.Context, req *sapb.CountCertificatesByNamesRequest, _ ...grpc.CallOption) (*sapb.CountByNames, error) {
	counts := make(map[string]int64)
	for _, name := range req.DnsNames {
		entry, ok := m.issuanceTimestamps[name]
		if ok {
			counts[name] = int64(len(entry.Timestamps))
		}
	}
	return &sapb.CountByNames{Counts: counts}, nil
}

func (m mockSAWithFQDNSet) CountFQDNSets(_ context.Context, req *sapb.CountFQDNSetsRequest, _ ...grpc.CallOption) (*sapb.Count, error) {
	var total int64
	for _, name := range req.DnsNames {
		entry, ok := m.issuanceTimestamps[name]
		if ok {
			total += int64(len(entry.Timestamps))
		}
	}
	return &sapb.Count{Count: total}, nil
}

func (m mockSAWithFQDNSet) FQDNSetTimestampsForWindow(_ context.Context, req *sapb.CountFQDNSetsRequest, _ ...grpc.CallOption) (*sapb.Timestamps, error) {
	if len(req.DnsNames) == 1 {
		return m.issuanceTimestamps[req.DnsNames[0]], nil
	} else {
		return nil, fmt.Errorf("FQDNSetTimestampsForWindow mock only supports a single domain")
	}
}

// TestExactPublicSuffixCertLimit tests the behaviour of issue #2681.
// See https://github.com/letsencrypt/boulder/issues/2681
func TestExactPublicSuffixCertLimit(t *testing.T) {
	_, _, ra, _, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Simple policy that only allows 2 certificates per name.
	certsPerNamePolicy := ratelimit.RateLimitPolicy{
		Threshold: 2,
		Window:    config.Duration{Duration: 23 * time.Hour},
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
		nameCounts: &sapb.CountByNames{
			Counts: map[string]int64{
				"test.dedyn.io":  1,
				"test2.dedyn.io": 1,
				"test3.dedyn.io": 0,
				"dedyn.io":       0,
				"dynv6.net":      2,
			},
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
	// "dynv6.net" is an exact public suffix match with 2 certificates issued for
	// it.
	err = ra.checkCertificatesPerNameLimit(ctx, []string{"test3.dedyn.io", "dynv6.net"}, certsPerNamePolicy, 99)
	test.AssertError(t, err, "certificate per name rate limit not applied correctly")
}

func TestDeactivateAuthorization(t *testing.T) {
	_, sa, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	exp := ra.clk.Now().Add(365 * 24 * time.Hour)
	authzID := createFinalizedAuthorization(t, sa, "not-example.com", exp, core.ChallengeTypeHTTP01, ra.clk.Now())
	dbAuthzPB := getAuthorization(t, fmt.Sprint(authzID), sa)
	_, err := ra.DeactivateAuthorization(ctx, dbAuthzPB)
	test.AssertNotError(t, err, "Could not deactivate authorization")
	deact, err := sa.GetAuthorization2(ctx, &sapb.AuthorizationID2{Id: authzID})
	test.AssertNotError(t, err, "Could not get deactivated authorization with ID "+dbAuthzPB.Id)
	test.AssertEquals(t, deact.Status, string(core.StatusDeactivated))
}

type mockSARecordingPauses struct {
	sapb.StorageAuthorityClient
	recv *sapb.PauseRequest
}

func (sa *mockSARecordingPauses) PauseIdentifiers(ctx context.Context, req *sapb.PauseRequest, _ ...grpc.CallOption) (*sapb.PauseIdentifiersResponse, error) {
	sa.recv = req
	return &sapb.PauseIdentifiersResponse{Paused: int64(len(req.Identifiers))}, nil
}

func (sa *mockSARecordingPauses) DeactivateAuthorization2(_ context.Context, _ *sapb.AuthorizationID2, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return nil, nil
}

func TestDeactivateAuthorization_Pausing(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	if ra.limiter == nil {
		t.Skip("no redis limiter configured")
	}

	msa := mockSARecordingPauses{}
	ra.SA = &msa

	features.Set(features.Config{AutomaticallyPauseZombieClients: true})
	defer features.Reset()

	// Override the default ratelimits to only allow one failed validation per
	// 24 hours before pausing.
	txnBuilder, err := ratelimits.NewTransactionBuilder(ratelimits.LimitConfigs{
		ratelimits.FailedAuthorizationsForPausingPerDomainPerAccount.String(): &ratelimits.LimitConfig{
			Burst:  1,
			Count:  1,
			Period: config.Duration{Duration: time.Hour * 24}},
	})
	test.AssertNotError(t, err, "making transaction composer")
	ra.txnBuilder = txnBuilder

	// The first deactivation of a pending authz should work and nothing should
	// get paused.
	_, err = ra.DeactivateAuthorization(ctx, &corepb.Authorization{
		Id:             "1",
		RegistrationID: 1,
		DnsName:        "example.com",
		Status:         string(core.StatusPending),
	})
	test.AssertNotError(t, err, "mock deactivation should work")
	test.AssertBoxedNil(t, msa.recv, "shouldn't be a pause request yet")

	// Deactivating a valid authz shouldn't increment any limits or pause anything.
	_, err = ra.DeactivateAuthorization(ctx, &corepb.Authorization{
		Id:             "2",
		RegistrationID: 1,
		DnsName:        "example.com",
		Status:         string(core.StatusValid),
	})
	test.AssertNotError(t, err, "mock deactivation should work")
	test.AssertBoxedNil(t, msa.recv, "deactivating valid authz should never pause")

	// Deactivating a second pending authz should surpass the limit and result
	// in a pause request.
	_, err = ra.DeactivateAuthorization(ctx, &corepb.Authorization{
		Id:             "3",
		RegistrationID: 1,
		DnsName:        "example.com",
		Status:         string(core.StatusPending),
	})
	test.AssertNotError(t, err, "mock deactivation should work")
	test.AssertNotNil(t, msa.recv, "should have recorded a pause request")
	test.AssertEquals(t, msa.recv.RegistrationID, int64(1))
	test.AssertEquals(t, msa.recv.Identifiers[0].Value, "example.com")
}

func TestDeactivateRegistration(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Deactivate failure because incomplete registration provided
	_, err := ra.DeactivateRegistration(context.Background(), &corepb.Registration{})
	test.AssertDeepEquals(t, err, fmt.Errorf("incomplete gRPC request message"))

	// Deactivate failure because registration status already deactivated
	_, err = ra.DeactivateRegistration(context.Background(),
		&corepb.Registration{Id: 1, Status: string(core.StatusDeactivated)})
	test.AssertError(t, err, "DeactivateRegistration failed with a non-valid registration")

	// Deactivate success with valid registration
	_, err = ra.DeactivateRegistration(context.Background(),
		&corepb.Registration{Id: 1, Status: string(core.StatusValid)})
	test.AssertNotError(t, err, "DeactivateRegistration failed")

	// Check db to make sure account is deactivated
	dbReg, err := ra.SA.GetRegistration(context.Background(), &sapb.RegistrationID{Id: 1})
	test.AssertNotError(t, err, "GetRegistration failed")
	test.AssertEquals(t, dbReg.Status, string(core.StatusDeactivated))
}

// noopCAA implements vapb.CAAClient, always returning nil
type noopCAA struct{}

func (cr noopCAA) IsCAAValid(
	ctx context.Context,
	in *vapb.IsCAAValidRequest,
	opts ...grpc.CallOption,
) (*vapb.IsCAAValidResponse, error) {
	return &vapb.IsCAAValidResponse{}, nil
}

func (cr noopCAA) DoCAA(
	ctx context.Context,
	in *vapb.IsCAAValidRequest,
	opts ...grpc.CallOption,
) (*vapb.IsCAAValidResponse, error) {
	return &vapb.IsCAAValidResponse{}, nil
}

// caaRecorder implements vapb.CAAClient, always returning nil, but recording
// the names it was called for.
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

func (cr *caaRecorder) DoCAA(
	ctx context.Context,
	in *vapb.IsCAAValidRequest,
	opts ...grpc.CallOption,
) (*vapb.IsCAAValidResponse, error) {
	cr.Lock()
	defer cr.Unlock()
	cr.names[in.Domain] = true
	return &vapb.IsCAAValidResponse{}, nil
}

// Test that the right set of domain names have their CAA rechecked, based on
// their `Validated` (attemptedAt in the database) timestamp.
func TestRecheckCAADates(t *testing.T) {
	_, _, ra, _, fc, cleanUp := initAuthorities(t)
	defer cleanUp()
	recorder := &caaRecorder{names: make(map[string]bool)}
	ra.VA = va.RemoteClients{CAAClient: recorder}
	ra.authorizationLifetime = 15 * time.Hour

	recentValidated := fc.Now().Add(-1 * time.Hour)
	recentExpires := fc.Now().Add(15 * time.Hour)
	olderValidated := fc.Now().Add(-8 * time.Hour)
	olderExpires := fc.Now().Add(5 * time.Hour)

	authzs := map[identifier.ACMEIdentifier]*core.Authorization{
		identifier.NewDNS("recent.com"): {
			Identifier: identifier.NewDNS("recent.com"),
			Expires:    &recentExpires,
			Challenges: []core.Challenge{
				{
					Status:    core.StatusValid,
					Type:      core.ChallengeTypeHTTP01,
					Token:     "exampleToken",
					Validated: &recentValidated,
				},
			},
		},
		identifier.NewDNS("older.com"): {
			Identifier: identifier.NewDNS("older.com"),
			Expires:    &olderExpires,
			Challenges: []core.Challenge{
				{
					Status:    core.StatusValid,
					Type:      core.ChallengeTypeHTTP01,
					Token:     "exampleToken",
					Validated: &olderValidated,
				},
			},
		},
		identifier.NewDNS("older2.com"): {
			Identifier: identifier.NewDNS("older2.com"),
			Expires:    &olderExpires,
			Challenges: []core.Challenge{
				{
					Status:    core.StatusValid,
					Type:      core.ChallengeTypeHTTP01,
					Token:     "exampleToken",
					Validated: &olderValidated,
				},
			},
		},
		identifier.NewDNS("wildcard.com"): {
			Identifier: identifier.NewDNS("wildcard.com"),
			Expires:    &olderExpires,
			Challenges: []core.Challenge{
				{
					Status:    core.StatusValid,
					Type:      core.ChallengeTypeHTTP01,
					Token:     "exampleToken",
					Validated: &olderValidated,
				},
			},
		},
		identifier.NewDNS("*.wildcard.com"): {
			Identifier: identifier.NewDNS("*.wildcard.com"),
			Expires:    &olderExpires,
			Challenges: []core.Challenge{
				{
					Status:    core.StatusValid,
					Type:      core.ChallengeTypeHTTP01,
					Token:     "exampleToken",
					Validated: &olderValidated,
				},
			},
		},
	}
	twoChallenges := map[identifier.ACMEIdentifier]*core.Authorization{
		identifier.NewDNS("twochallenges.com"): {
			ID:         "twochal",
			Identifier: identifier.NewDNS("twochallenges.com"),
			Expires:    &recentExpires,
			Challenges: []core.Challenge{
				{
					Status:    core.StatusValid,
					Type:      core.ChallengeTypeHTTP01,
					Token:     "exampleToken",
					Validated: &olderValidated,
				},
				{
					Status:    core.StatusValid,
					Type:      core.ChallengeTypeDNS01,
					Token:     "exampleToken",
					Validated: &olderValidated,
				},
			},
		},
	}
	noChallenges := map[identifier.ACMEIdentifier]*core.Authorization{
		identifier.NewDNS("nochallenges.com"): {
			ID:         "nochal",
			Identifier: identifier.NewDNS("nochallenges.com"),
			Expires:    &recentExpires,
			Challenges: []core.Challenge{},
		},
	}
	noValidationTime := map[identifier.ACMEIdentifier]*core.Authorization{
		identifier.NewDNS("novalidationtime.com"): {
			ID:         "noval",
			Identifier: identifier.NewDNS("novalidationtime.com"),
			Expires:    &recentExpires,
			Challenges: []core.Challenge{
				{
					Status:    core.StatusValid,
					Type:      core.ChallengeTypeHTTP01,
					Token:     "exampleToken",
					Validated: nil,
				},
			},
		},
	}

	// NOTE: The names provided here correspond to authorizations in the
	// `mockSAWithRecentAndOlder`
	err := ra.checkAuthorizationsCAA(context.Background(), Registration.Id, authzs, fc.Now())
	// We expect that there is no error rechecking authorizations for these names
	if err != nil {
		t.Errorf("expected nil err, got %s", err)
	}

	// Should error if a authorization has `!= 1` challenge
	err = ra.checkAuthorizationsCAA(context.Background(), Registration.Id, twoChallenges, fc.Now())
	test.AssertEquals(t, err.Error(), "authorization has incorrect number of challenges. 1 expected, 2 found for: id twochal")

	// Should error if a authorization has `!= 1` challenge
	err = ra.checkAuthorizationsCAA(context.Background(), Registration.Id, noChallenges, fc.Now())
	test.AssertEquals(t, err.Error(), "authorization has incorrect number of challenges. 1 expected, 0 found for: id nochal")

	// Should error if authorization's challenge has no validated timestamp
	err = ra.checkAuthorizationsCAA(context.Background(), Registration.Id, noValidationTime, fc.Now())
	test.AssertEquals(t, err.Error(), "authorization's challenge has no validated timestamp for: id noval")

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
			Detail: "CAA invalid for a.com",
		}
	case "c.com":
		cvrpb.Problem = &corepb.ProblemDetails{
			Detail: "CAA invalid for c.com",
		}
	case "d.com":
		return nil, fmt.Errorf("Error checking CAA for d.com")
	}
	return cvrpb, nil
}

func (cf *caaFailer) DoCAA(
	ctx context.Context,
	in *vapb.IsCAAValidRequest,
	opts ...grpc.CallOption,
) (*vapb.IsCAAValidResponse, error) {
	cvrpb := &vapb.IsCAAValidResponse{}
	switch in.Domain {
	case "a.com":
		cvrpb.Problem = &corepb.ProblemDetails{
			Detail: "CAA invalid for a.com",
		}
	case "c.com":
		cvrpb.Problem = &corepb.ProblemDetails{
			Detail: "CAA invalid for c.com",
		}
	case "d.com":
		return nil, fmt.Errorf("Error checking CAA for d.com")
	}
	return cvrpb, nil
}

func TestRecheckCAAEmpty(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	err := ra.recheckCAA(context.Background(), nil)
	test.AssertNotError(t, err, "expected nil")
}

func makeHTTP01Authorization(domain string) *core.Authorization {
	return &core.Authorization{
		Identifier: identifier.NewDNS(domain),
		Challenges: []core.Challenge{{Status: core.StatusValid, Type: core.ChallengeTypeHTTP01}},
	}
}

func TestRecheckCAASuccess(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.VA = va.RemoteClients{CAAClient: &noopCAA{}}
	authzs := []*core.Authorization{
		makeHTTP01Authorization("a.com"),
		makeHTTP01Authorization("b.com"),
		makeHTTP01Authorization("c.com"),
	}
	err := ra.recheckCAA(context.Background(), authzs)
	test.AssertNotError(t, err, "expected nil")
}

func TestRecheckCAAFail(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.VA = va.RemoteClients{CAAClient: &caaFailer{}}
	authzs := []*core.Authorization{
		makeHTTP01Authorization("a.com"),
		makeHTTP01Authorization("b.com"),
		makeHTTP01Authorization("c.com"),
	}
	err := ra.recheckCAA(context.Background(), authzs)

	test.AssertError(t, err, "expected err, got nil")
	var berr *berrors.BoulderError
	test.AssertErrorWraps(t, err, &berr)
	test.AssertErrorIs(t, berr, berrors.CAA)
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
	test.AssertErrorWraps(t, err, &berr)
	// There should be *no* suberrors because there was only one overall error
	test.AssertEquals(t, len(berr.SubErrors), 0)
}

func TestRecheckCAAInternalServerError(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.VA = va.RemoteClients{CAAClient: &caaFailer{}}
	authzs := []*core.Authorization{
		makeHTTP01Authorization("a.com"),
		makeHTTP01Authorization("b.com"),
		makeHTTP01Authorization("d.com"),
	}
	err := ra.recheckCAA(context.Background(), authzs)
	test.AssertError(t, err, "expected err, got nil")
	test.AssertErrorIs(t, err, berrors.InternalServer)
}

func TestNewOrder(t *testing.T) {
	_, _, ra, _, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	now := fc.Now()
	orderA, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID:         Registration.Id,
		CertificateProfileName: "test",
		DnsNames:               []string{"b.com", "a.com", "a.com", "C.COM"},
	})
	test.AssertNotError(t, err, "ra.NewOrder failed")
	test.AssertEquals(t, orderA.RegistrationID, int64(1))
	test.AssertEquals(t, orderA.Expires.AsTime(), now.Add(ra.orderLifetime))
	test.AssertEquals(t, len(orderA.DnsNames), 3)
	test.AssertEquals(t, orderA.CertificateProfileName, "test")
	// We expect the order names to have been sorted, deduped, and lowercased
	test.AssertDeepEquals(t, orderA.DnsNames, []string{"a.com", "b.com", "c.com"})
	test.AssertEquals(t, orderA.Id, int64(1))
	test.AssertEquals(t, numAuthorizations(orderA), 3)

	_, err = ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.Id,
		DnsNames:       []string{"a"},
	})
	test.AssertError(t, err, "NewOrder with invalid names did not error")
	test.AssertEquals(t, err.Error(), "Cannot issue for \"a\": Domain name needs at least one dot")
}

// TestNewOrderReuse tests that subsequent requests by an ACME account to create
// an identical order results in only one order being created & subsequently
// reused.
func TestNewOrder_OrderReusex(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Create an initial order with regA and names
	names := []string{"zombo.com", "welcome.to.zombo.com"}
	orderReq := &rapb.NewOrderRequest{
		RegistrationID: Registration.Id,
		DnsNames:       names,
	}
	firstOrder, err := ra.NewOrder(context.Background(), orderReq)
	test.AssertNotError(t, err, "Adding an initial order for regA failed")

	// Create a second registration to reference
	acctKeyB, err := AccountKeyB.MarshalJSON()
	test.AssertNotError(t, err, "failed to marshal account key")
	input := &corepb.Registration{Key: acctKeyB}
	secondReg, err := ra.NewRegistration(context.Background(), input)
	test.AssertNotError(t, err, "Error creating a second test registration")

	testCases := []struct {
		Name           string
		RegistrationID int64
		DnsNames       []string
		ExpectReuse    bool
	}{
		{
			Name:           "Duplicate order, same regID",
			RegistrationID: Registration.Id,
			DnsNames:       names,
			// We expect reuse since the order matches firstOrder
			ExpectReuse: true,
		},
		{
			Name:           "Subset of order names, same regID",
			RegistrationID: Registration.Id,
			DnsNames:       names[:1],
			// We do not expect reuse because the order names don't match firstOrder
			ExpectReuse: false,
		},
		{
			Name:           "Superset of order names, same regID",
			RegistrationID: Registration.Id,
			DnsNames:       append(names, "blog.zombo.com"),
			// We do not expect reuse because the order names don't match firstOrder
			ExpectReuse: false,
		},
		{
			Name:           "Duplicate order, different regID",
			RegistrationID: secondReg.Id,
			DnsNames:       names,
			// We do not expect reuse because the order regID differs from firstOrder
			ExpectReuse: false,
		},
		// TODO(#7324): Integrate certificate profile variance into this test.
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Add the order for the test request
			order, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
				RegistrationID: tc.RegistrationID,
				DnsNames:       tc.DnsNames,
			})
			test.AssertNotError(t, err, "NewOrder returned an unexpected error")
			test.AssertNotNil(t, order.Id, "NewOrder returned an order with a nil Id")

			if tc.ExpectReuse {
				// If we expected order reuse for this testcase assert that the order
				// has the same ID as the firstOrder
				test.AssertEquals(t, order.Id, firstOrder.Id)
			} else {
				// Otherwise assert that the order doesn't have the same ID as the
				// firstOrder
				test.AssertNotEquals(t, order.Id, firstOrder.Id)
			}
		})
	}
}

// TestNewOrder_OrderReuse_Profile tests that order reuse respects profiles.
// This is not simply a test case in TestNewOrder_OrderReuse because it relies
// on feature-flag gated behavior. It should be unified with that function when
// the feature flag is removed.
func TestNewOrder_OrderReuse_Profile(t *testing.T) {
	// TODO(#7324): Integrate these cases into TestNewOrder_OrderReuse.
	if !strings.Contains(os.Getenv("BOULDER_CONFIG_DIR"), "test/config-next") {
		t.Skip("this test requires the db to have the certificateProfileName column in the orders table")
	}

	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	features.Set(features.Config{MultipleCertificateProfiles: true})
	defer features.Reset()

	// Create an initial order with a profile name.
	extant, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID:         Registration.Id,
		CertificateProfileName: "test",
		DnsNames:               []string{"a.com", "b.com"},
	})
	test.AssertNotError(t, err, "creating test order")

	// Creating an identical order should reuse the first one.
	new, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID:         Registration.Id,
		CertificateProfileName: "test",
		DnsNames:               []string{"a.com", "b.com"},
	})
	test.AssertNotError(t, err, "creating test order")
	test.AssertEquals(t, new.Id, extant.Id)

	// Creating a new order for the same names but a different profile should not
	// reuse the first one.
	new, err = ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID:         Registration.Id,
		CertificateProfileName: "test2",
		DnsNames:               []string{"a.com", "b.com"},
	})
	test.AssertNotError(t, err, "creating test order")
	test.AssertNotEquals(t, new.Id, extant.Id)
}

// TestNewOrder_OrderReuse_Expired tests that expired orders are not reused.
// This is not simply a test case in TestNewOrder_OrderReuse because it has
// side effects.
func TestNewOrder_OrderReuse_Expired(t *testing.T) {
	_, _, ra, _, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Set the order lifetime to something short and known.
	ra.orderLifetime = time.Hour

	// Create an initial order.
	extant, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.Id,
		DnsNames:       []string{"a.com", "b.com"},
	})
	test.AssertNotError(t, err, "creating test order")

	// Transition the original order to status invalid by jumping forward in time
	// to when it has expired.
	fc.Set(extant.Expires.AsTime().Add(2 * time.Hour))

	// Now a new order for the same names should not reuse the first one.
	new, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.Id,
		DnsNames:       []string{"a.com", "b.com"},
	})
	test.AssertNotError(t, err, "creating test order")
	test.AssertNotEquals(t, new.Id, extant.Id)
}

// TestNewOrder_OrderReuse_Invalid tests that invalid orders are not reused.
// This is not simply a test case in TestNewOrder_OrderReuse because it has
// side effects.
func TestNewOrder_OrderReuse_Invalid(t *testing.T) {
	_, sa, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Create an initial order.
	extant, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.Id,
		DnsNames:       []string{"a.com", "b.com"},
	})
	test.AssertNotError(t, err, "creating test order")

	// Transition the original order to status invalid by invalidating one of its
	// authorizations.
	_, err = sa.DeactivateAuthorization2(context.Background(), &sapb.AuthorizationID2{
		Id: extant.V2Authorizations[0],
	})
	test.AssertNotError(t, err, "deactivating test authorization")

	// Now a new order for the same names should not reuse the first one.
	new, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.Id,
		DnsNames:       []string{"a.com", "b.com"},
	})
	test.AssertNotError(t, err, "creating test order")
	test.AssertNotEquals(t, new.Id, extant.Id)
}

func TestNewOrder_AuthzReuse(t *testing.T) {
	_, sa, ra, _, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Create three initial authzs by creating an initial order, then updating
	// the individual authz statuses.
	const (
		pending = "a-pending.com"
		valid   = "b-valid.com"
		invalid = "c-invalid.com"
	)
	extant, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.Id,
		DnsNames:       []string{pending, valid, invalid},
	})
	test.AssertNotError(t, err, "creating test order")
	extantAuthzs := map[string]int64{
		// Take advantage of the fact that authz IDs are returned in the same order
		// as the lexicographically-sorted identifiers.
		pending: extant.V2Authorizations[0],
		valid:   extant.V2Authorizations[1],
		invalid: extant.V2Authorizations[2],
	}
	_, err = sa.FinalizeAuthorization2(context.Background(), &sapb.FinalizeAuthorizationRequest{
		Id:        extantAuthzs[valid],
		Status:    string(core.StatusValid),
		Attempted: "hello",
		Expires:   timestamppb.New(fc.Now().Add(48 * time.Hour)),
	})
	test.AssertNotError(t, err, "marking test authz as valid")
	_, err = sa.DeactivateAuthorization2(context.Background(), &sapb.AuthorizationID2{
		Id: extantAuthzs[invalid],
	})
	test.AssertNotError(t, err, "marking test authz as invalid")

	// Create a second registration to reference later.
	acctKeyB, err := AccountKeyB.MarshalJSON()
	test.AssertNotError(t, err, "failed to marshal account key")
	input := &corepb.Registration{Key: acctKeyB}
	secondReg, err := ra.NewRegistration(context.Background(), input)
	test.AssertNotError(t, err, "Error creating a second test registration")

	testCases := []struct {
		Name           string
		RegistrationID int64
		DnsName        string
		ExpectReuse    bool
	}{
		{
			Name:           "Reuse pending authz",
			RegistrationID: Registration.Id,
			DnsName:        pending,
			ExpectReuse:    true, // TODO(#7715): Invert this.
		},
		{
			Name:           "Reuse valid authz",
			RegistrationID: Registration.Id,
			DnsName:        valid,
			ExpectReuse:    true,
		},
		{
			Name:           "Don't reuse invalid authz",
			RegistrationID: Registration.Id,
			DnsName:        invalid,
			ExpectReuse:    false,
		},
		{
			Name:           "Don't reuse valid authz from other acct",
			RegistrationID: secondReg.Id,
			DnsName:        valid,
			ExpectReuse:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			new, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
				RegistrationID: tc.RegistrationID,
				DnsNames:       []string{tc.DnsName},
			})
			test.AssertNotError(t, err, "creating test order")
			test.AssertNotEquals(t, new.Id, extant.Id)

			if tc.ExpectReuse {
				test.AssertEquals(t, new.V2Authorizations[0], extantAuthzs[tc.DnsName])
			} else {
				test.AssertNotEquals(t, new.V2Authorizations[0], extantAuthzs[tc.DnsName])
			}
		})
	}
}

// TestNewOrder_AuthzReuse_NoPending tests that authz reuse doesn't reuse
// pending authzs when a feature flag is set.
// This is not simply a test case in TestNewOrder_OrderReuse because it relies
// on feature-flag gated behavior. It should be unified with that function when
// the feature flag is removed.
func TestNewOrder_AuthzReuse_NoPending(t *testing.T) {
	// TODO(#7715): Integrate these cases into TestNewOrder_AuthzReuse.
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	features.Set(features.Config{NoPendingAuthzReuse: true})
	defer features.Reset()

	// Create an initial order and two pending authzs.
	extant, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.Id,
		DnsNames:       []string{"a.com", "b.com"},
	})
	test.AssertNotError(t, err, "creating test order")

	// With the feature flag enabled, creating a new order for one of these names
	// should not reuse the existing pending authz.
	new, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.Id,
		DnsNames:       []string{"a.com"},
	})
	test.AssertNotError(t, err, "creating test order")
	test.AssertNotEquals(t, new.Id, extant.Id)
	test.AssertNotEquals(t, new.V2Authorizations[0], extant.V2Authorizations[0])
}

// mockSAWithAuthzs has a GetAuthorizations2 method that returns the protobuf
// version of its authzs struct member. It also has a fake GetOrderForNames
// which always fails, and a fake NewOrderAndAuthzs which always succeeds, to
// facilitate the full execution of RA.NewOrder.
type mockSAWithAuthzs struct {
	sapb.StorageAuthorityClient
	authzs []*core.Authorization
}

// GetOrderForNames is a mock which always returns NotFound so that NewOrder
// proceeds to attempt authz reuse instead of wholesale order reuse.
func (msa *mockSAWithAuthzs) GetOrderForNames(ctx context.Context, req *sapb.GetOrderForNamesRequest, _ ...grpc.CallOption) (*corepb.Order, error) {
	return nil, berrors.NotFoundError("no such order")
}

// GetValidAuthorizations2 returns a _bizarre_ authorization for "*.zombo.com" that
// was validated by HTTP-01. This should never happen in real life since the
// name is a wildcard. We use this mock to test that we reject this bizarre
// situation correctly.
func (msa *mockSAWithAuthzs) GetValidAuthorizations2(ctx context.Context, req *sapb.GetValidAuthorizationsRequest, _ ...grpc.CallOption) (*sapb.Authorizations, error) {
	resp := &sapb.Authorizations{}
	for _, v := range msa.authzs {
		authzPB, err := bgrpc.AuthzToPB(*v)
		if err != nil {
			return nil, err
		}
		resp.Authzs = append(resp.Authzs, authzPB)
	}
	return resp, nil
}

func (msa *mockSAWithAuthzs) GetAuthorizations2(ctx context.Context, req *sapb.GetAuthorizationsRequest, _ ...grpc.CallOption) (*sapb.Authorizations, error) {
	return msa.GetValidAuthorizations2(ctx, &sapb.GetValidAuthorizationsRequest{
		RegistrationID: req.RegistrationID,
		DnsNames:       req.DnsNames,
		ValidUntil:     req.ValidUntil,
	})
}

func (msa *mockSAWithAuthzs) GetAuthorization2(ctx context.Context, req *sapb.AuthorizationID2, _ ...grpc.CallOption) (*corepb.Authorization, error) {
	for _, authz := range msa.authzs {
		if authz.ID == fmt.Sprintf("%d", req.Id) {
			return bgrpc.AuthzToPB(*authz)
		}
	}
	return nil, berrors.NotFoundError("no such authz")
}

// NewOrderAndAuthzs is a mock which just reflects the incoming request back,
// pretending to have created new db rows for the requested newAuthzs.
func (msa *mockSAWithAuthzs) NewOrderAndAuthzs(ctx context.Context, req *sapb.NewOrderAndAuthzsRequest, _ ...grpc.CallOption) (*corepb.Order, error) {
	authzIDs := req.NewOrder.V2Authorizations
	for range req.NewAuthzs {
		authzIDs = append(authzIDs, mrand.Int64())
	}
	return &corepb.Order{
		// Fields from the input new order request.
		RegistrationID:         req.NewOrder.RegistrationID,
		Expires:                req.NewOrder.Expires,
		DnsNames:               req.NewOrder.DnsNames,
		V2Authorizations:       authzIDs,
		CertificateProfileName: req.NewOrder.CertificateProfileName,
		// Mock new fields generated by the database transaction.
		Id:      mrand.Int64(),
		Created: timestamppb.Now(),
		// A new order is never processing because it can't have been finalized yet.
		BeganProcessing: false,
		Status:          string(core.StatusPending),
	}, nil
}

// TestNewOrderAuthzReuseSafety checks that the RA's safety check for reusing an
// authorization for a new-order request with a wildcard name works correctly.
// We want to ensure that we never reuse a non-Wildcard authorization (e.g. one
// with more than just a DNS-01 challenge) for a wildcard name. See Issue #3420
// for background - this safety check was previously broken!
// https://github.com/letsencrypt/boulder/issues/3420
func TestNewOrderAuthzReuseSafety(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	ctx := context.Background()
	names := []string{"*.zombo.com"}

	// Use a mock SA that always returns a valid HTTP-01 authz for the name
	// "zombo.com"
	expires := time.Now()
	ra.SA = &mockSAWithAuthzs{
		authzs: []*core.Authorization{
			{
				// A static fake ID we can check for in a unit test
				ID:             "1",
				Identifier:     identifier.NewDNS("*.zombo.com"),
				RegistrationID: Registration.Id,
				// Authz is valid
				Status:  "valid",
				Expires: &expires,
				Challenges: []core.Challenge{
					// HTTP-01 challenge is valid
					{
						Type:   core.ChallengeTypeHTTP01, // The dreaded HTTP-01! X__X
						Status: core.StatusValid,
						Token:  core.NewToken(),
					},
					// DNS-01 challenge is pending
					{
						Type:   core.ChallengeTypeDNS01,
						Status: core.StatusPending,
						Token:  core.NewToken(),
					},
				},
			},
			{
				// A static fake ID we can check for in a unit test
				ID:             "2",
				Identifier:     identifier.NewDNS("zombo.com"),
				RegistrationID: Registration.Id,
				// Authz is valid
				Status:  "valid",
				Expires: &expires,
				Challenges: []core.Challenge{
					// HTTP-01 challenge is valid
					{
						Type:   core.ChallengeTypeHTTP01,
						Status: core.StatusValid,
						Token:  core.NewToken(),
					},
					// DNS-01 challenge is pending
					{
						Type:   core.ChallengeTypeDNS01,
						Status: core.StatusPending,
						Token:  core.NewToken(),
					},
				},
			},
		},
	}

	// Create an initial request with regA and names
	orderReq := &rapb.NewOrderRequest{
		RegistrationID: Registration.Id,
		DnsNames:       names,
	}

	// Create an order for that request
	order, err := ra.NewOrder(ctx, orderReq)
	// It shouldn't fail
	test.AssertNotError(t, err, "Adding an initial order for regA failed")
	test.AssertEquals(t, numAuthorizations(order), 1)
	// It should *not* be the bad authorization!
	test.AssertNotEquals(t, order.V2Authorizations[0], int64(1))
}

func TestNewOrderWildcard(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	orderNames := []string{"example.com", "*.welcome.zombo.com"}
	wildcardOrderRequest := &rapb.NewOrderRequest{
		RegistrationID: Registration.Id,
		DnsNames:       orderNames,
	}

	order, err := ra.NewOrder(context.Background(), wildcardOrderRequest)
	test.AssertNotError(t, err, "NewOrder failed for a wildcard order request")

	// We expect the order to be pending
	test.AssertEquals(t, order.Status, string(core.StatusPending))
	// We expect the order to have two names
	test.AssertEquals(t, len(order.DnsNames), 2)
	// We expect the order to have the names we requested
	test.AssertDeepEquals(t,
		core.UniqueLowerNames(order.DnsNames),
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
		RegistrationID: Registration.Id,
		DnsNames:       orderNames,
	}
	order, err = ra.NewOrder(context.Background(), wildcardOrderRequest)
	test.AssertNotError(t, err, "NewOrder failed for a wildcard order request")

	// We expect the order to be pending
	test.AssertEquals(t, order.Status, string(core.StatusPending))
	// We expect the order to have two names
	test.AssertEquals(t, len(order.DnsNames), 2)
	// We expect the order to have the names we requested
	test.AssertDeepEquals(t,
		core.UniqueLowerNames(order.DnsNames),
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
		RegistrationID: Registration.Id,
		DnsNames:       []string{"everything.is.possible.zombo.com"},
	}
	normalOrder, err := ra.NewOrder(context.Background(), normalOrderReq)
	test.AssertNotError(t, err, "NewOrder failed for a normal non-wildcard order")

	test.AssertEquals(t, numAuthorizations(normalOrder), 1)
	// We expect the order is in Pending status
	test.AssertEquals(t, order.Status, string(core.StatusPending))
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
	test.AssertEquals(t, len(authz.Challenges), 3)

	// Now submit an order request for a wildcard of the domain we just created an
	// order for. We should **NOT** reuse the authorization from the previous
	// order since we now require a DNS-01 challenge for the `*.` prefixed name.
	orderNames = []string{"*.everything.is.possible.zombo.com"}
	wildcardOrderRequest = &rapb.NewOrderRequest{
		RegistrationID: Registration.Id,
		DnsNames:       orderNames,
	}
	order, err = ra.NewOrder(context.Background(), wildcardOrderRequest)
	test.AssertNotError(t, err, "NewOrder failed for a wildcard order request")
	// We expect the order is in Pending status
	test.AssertEquals(t, order.Status, string(core.StatusPending))
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
	test.AssertEquals(t, dupeOrder.Status, string(core.StatusPending))
	test.AssertEquals(t, numAuthorizations(dupeOrder), 1)
	// The authz should be the same ID as the previous order's authz. We already
	// checked that order.Authorizations[0] only has a DNS-01 challenge above so
	// we don't need to recheck that here.
	test.AssertEquals(t, dupeOrder.V2Authorizations[0], order.V2Authorizations[0])
}

func TestNewOrderExpiry(t *testing.T) {
	_, _, ra, _, clk, cleanUp := initAuthorities(t)
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
	ra.SA = &mockSAWithAuthzs{
		authzs: []*core.Authorization{
			{
				// A static fake ID we can check for in a unit test
				ID:             "1",
				Identifier:     identifier.NewDNS("zombo.com"),
				RegistrationID: Registration.Id,
				Expires:        &fakeAuthzExpires,
				Status:         "valid",
				Challenges: []core.Challenge{
					{
						Type:   core.ChallengeTypeHTTP01,
						Status: core.StatusValid,
						Token:  core.NewToken(),
					},
				},
			},
		},
	}

	// Create an initial request with regA and names
	orderReq := &rapb.NewOrderRequest{
		RegistrationID: Registration.Id,
		DnsNames:       names,
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
	test.AssertEquals(t, order.Expires.AsTime(), fakeAuthzExpires)

	// Set the order lifetime to be lower than the fakeAuthzLifetime
	ra.orderLifetime = 12 * time.Hour
	expectedOrderExpiry := clk.Now().Add(ra.orderLifetime)
	// Create the order again
	order, err = ra.NewOrder(ctx, orderReq)
	// It shouldn't fail
	test.AssertNotError(t, err, "Adding an order for regA failed")
	test.AssertEquals(t, numAuthorizations(order), 1)
	// It should be the fake near-expired-authz authz
	test.AssertEquals(t, order.V2Authorizations[0], int64(1))
	// The order's expiry should be the order's own expiry since it is sooner than
	// the fake authz's expiry.
	test.AssertEquals(t, order.Expires.AsTime(), expectedOrderExpiry)
}

func TestFinalizeOrder(t *testing.T) {
	_, sa, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Create one finalized authorization for not-example.com and one finalized
	// authorization for www.not-example.org
	now := ra.clk.Now()
	exp := now.Add(365 * 24 * time.Hour)
	authzIDA := createFinalizedAuthorization(t, sa, "not-example.com", exp, core.ChallengeTypeHTTP01, ra.clk.Now())
	authzIDB := createFinalizedAuthorization(t, sa, "www.not-example.com", exp, core.ChallengeTypeHTTP01, ra.clk.Now())

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
		DNSNames:           []string{"a.com"},
	}, testKey)
	test.AssertNotError(t, err, "Error creating CSR with one DNS name")

	twoDomainCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		PublicKey:          testKey.PublicKey,
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           []string{"a.com", "b.com"},
	}, testKey)
	test.AssertNotError(t, err, "Error creating CSR with two DNS names")

	validCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		PublicKey:          testKey.Public(),
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           []string{"not-example.com", "www.not-example.com"},
	}, testKey)
	test.AssertNotError(t, err, "Error creating CSR with authorized names")

	expectedCert := &x509.Certificate{
		SerialNumber:          big.NewInt(0),
		Subject:               pkix.Name{CommonName: "not-example.com"},
		DNSNames:              []string{"not-example.com", "www.not-example.com"},
		PublicKey:             testKey.Public(),
		NotBefore:             now,
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, expectedCert, expectedCert, testKey.Public(), testKey)
	test.AssertNotError(t, err, "failed to construct test certificate")
	ra.CA.(*mocks.MockCA).PEM = pem.EncodeToMemory(&pem.Block{Bytes: certDER, Type: "CERTIFICATE"})

	fakeRegID := int64(0xB00)

	// NOTE(@cpu): We use unique `names` for each of these orders because
	// otherwise only *one* order is created & reused. The first test case to
	// finalize the order will put it into processing state and the other tests
	// will fail because you can't finalize an order that is already being
	// processed.
	// Add a new order for the fake reg ID
	fakeRegOrder, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.Id,
		DnsNames:       []string{"001.example.com"},
	})
	test.AssertNotError(t, err, "Could not add test order for fake reg ID order ID")

	missingAuthzOrder, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.Id,
		DnsNames:       []string{"002.example.com"},
	})
	test.AssertNotError(t, err, "Could not add test order for missing authz order ID")

	validatedOrder, err := sa.NewOrderAndAuthzs(context.Background(), &sapb.NewOrderAndAuthzsRequest{
		NewOrder: &sapb.NewOrderRequest{
			RegistrationID:   Registration.Id,
			Expires:          timestamppb.New(exp),
			DnsNames:         []string{"not-example.com", "www.not-example.com"},
			V2Authorizations: []int64{authzIDA, authzIDB},
		},
	})
	test.AssertNotError(t, err, "Could not add test order with finalized authz IDs, ready status")

	testCases := []struct {
		Name           string
		OrderReq       *rapb.FinalizeOrderRequest
		ExpectedErrMsg string
		ExpectIssuance bool
	}{
		{
			Name: "No id in order",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{},
				Csr:   oneDomainCSR,
			},
			ExpectedErrMsg: "invalid order ID: 0",
		},
		{
			Name: "No account id in order",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Id: 1,
				},
				Csr: oneDomainCSR,
			},
			ExpectedErrMsg: "invalid account ID: 0",
		},
		{
			Name: "No names in order",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Id:             1,
					RegistrationID: 1,
					Status:         string(core.StatusReady),
					DnsNames:       []string{},
				},
				Csr: oneDomainCSR,
			},
			ExpectedErrMsg: "Order has no associated names",
		},
		{
			Name: "Wrong order state (valid)",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Id:             1,
					RegistrationID: 1,
					Status:         string(core.StatusValid),
					DnsNames:       []string{"a.com"},
				},
				Csr: oneDomainCSR,
			},
			ExpectedErrMsg: `Order's status ("valid") is not acceptable for finalization`,
		},
		{
			Name: "Wrong order state (pending)",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Id:             1,
					RegistrationID: 1,
					Status:         string(core.StatusPending),
					DnsNames:       []string{"a.com"},
				},
				Csr: oneDomainCSR,
			},
			ExpectIssuance: false,
			ExpectedErrMsg: `Order's status ("pending") is not acceptable for finalization`,
		},
		{
			Name: "Invalid CSR",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Id:             1,
					RegistrationID: 1,
					Status:         string(core.StatusReady),
					DnsNames:       []string{"a.com"},
				},
				Csr: []byte{0xC0, 0xFF, 0xEE},
			},
			ExpectedErrMsg: "unable to parse CSR: asn1: syntax error: truncated tag or length",
		},
		{
			Name: "CSR and Order with diff number of names",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Id:             1,
					RegistrationID: 1,
					Status:         string(core.StatusReady),
					DnsNames:       []string{"a.com", "b.com"},
				},
				Csr: oneDomainCSR,
			},
			ExpectedErrMsg: "CSR does not specify same identifiers as Order",
		},
		{
			Name: "CSR and Order with diff number of names (other way)",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Id:             1,
					RegistrationID: 1,
					Status:         string(core.StatusReady),
					DnsNames:       []string{"a.com"},
				},
				Csr: twoDomainCSR,
			},
			ExpectedErrMsg: "CSR does not specify same identifiers as Order",
		},
		{
			Name: "CSR missing an order name",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Id:             1,
					RegistrationID: 1,
					Status:         string(core.StatusReady),
					DnsNames:       []string{"foobar.com"},
				},
				Csr: oneDomainCSR,
			},
			ExpectedErrMsg: "CSR does not specify same identifiers as Order",
		},
		{
			Name: "CSR with policy forbidden name",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Id:                1,
					RegistrationID:    1,
					Status:            string(core.StatusReady),
					DnsNames:          []string{"example.org"},
					Expires:           timestamppb.New(exp),
					CertificateSerial: "",
					BeganProcessing:   false,
				},
				Csr: policyForbidCSR,
			},
			ExpectedErrMsg: "Cannot issue for \"example.org\": The ACME server refuses to issue a certificate for this domain name, because it is forbidden by policy",
		},
		{
			Name: "Order with missing registration",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Status:            string(core.StatusReady),
					DnsNames:          []string{"a.com"},
					Id:                fakeRegOrder.Id,
					RegistrationID:    fakeRegID,
					Expires:           timestamppb.New(exp),
					CertificateSerial: "",
					BeganProcessing:   false,
					Created:           timestamppb.New(now),
				},
				Csr: oneDomainCSR,
			},
			ExpectedErrMsg: fmt.Sprintf("registration with ID '%d' not found", fakeRegID),
		},
		{
			Name: "Order with missing authorizations",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: &corepb.Order{
					Status:            string(core.StatusReady),
					DnsNames:          []string{"a.com", "b.com"},
					Id:                missingAuthzOrder.Id,
					RegistrationID:    Registration.Id,
					Expires:           timestamppb.New(exp),
					CertificateSerial: "",
					BeganProcessing:   false,
					Created:           timestamppb.New(now),
				},
				Csr: twoDomainCSR,
			},
			ExpectedErrMsg: "authorizations for these identifiers not found: a.com, b.com",
		},
		{
			Name: "Order with correct authorizations, ready status",
			OrderReq: &rapb.FinalizeOrderRequest{
				Order: validatedOrder,
				Csr:   validCSR,
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
				test.AssertNotEquals(t, updatedOrder.CertificateSerial, "")
				test.AssertEquals(t, updatedOrder.Status, "valid")
				test.AssertEquals(t, updatedOrder.Expires.AsTime(), exp)
			}
		})
	}
}

func TestFinalizeOrderWithMixedSANAndCN(t *testing.T) {
	_, sa, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Pick an expiry in the future
	now := ra.clk.Now()
	exp := now.Add(365 * 24 * time.Hour)

	// Create one finalized authorization for Registration.Id for not-example.com and
	// one finalized authorization for Registration.Id for www.not-example.org
	authzIDA := createFinalizedAuthorization(t, sa, "not-example.com", exp, core.ChallengeTypeHTTP01, ra.clk.Now())
	authzIDB := createFinalizedAuthorization(t, sa, "www.not-example.com", exp, core.ChallengeTypeHTTP01, ra.clk.Now())

	// Create a new order to finalize with names in SAN and CN
	mixedOrder, err := sa.NewOrderAndAuthzs(context.Background(), &sapb.NewOrderAndAuthzsRequest{
		NewOrder: &sapb.NewOrderRequest{
			RegistrationID:   Registration.Id,
			Expires:          timestamppb.New(exp),
			DnsNames:         []string{"not-example.com", "www.not-example.com"},
			V2Authorizations: []int64{authzIDA, authzIDB},
		},
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
		&sapb.OrderRequest{Id: mixedOrder.Id})
	test.AssertNotError(t, err, "Error getting order to check serial")
	test.AssertNotEquals(t, updatedOrder.CertificateSerial, "")
	test.AssertEquals(t, updatedOrder.Status, "valid")
}

func TestFinalizeOrderWildcard(t *testing.T) {
	_, sa, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Pick an expiry in the future
	now := ra.clk.Now()
	exp := now.Add(365 * 24 * time.Hour)

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
		RegistrationID: Registration.Id,
		DnsNames:       orderNames,
	}
	order, err := ra.NewOrder(context.Background(), wildcardOrderRequest)
	test.AssertNotError(t, err, "NewOrder failed for wildcard domain order")

	// Create one standard finalized authorization for Registration.Id for zombo.com
	_ = createFinalizedAuthorization(t, sa, "zombo.com", exp, core.ChallengeTypeHTTP01, ra.clk.Now())

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
	expires := now.Add(time.Hour * 24 * 7)
	_, err = sa.FinalizeAuthorization2(ctx, &sapb.FinalizeAuthorizationRequest{
		Id:          validOrder.V2Authorizations[0],
		Status:      string(core.StatusValid),
		Expires:     timestamppb.New(expires),
		Attempted:   string(core.ChallengeTypeDNS01),
		AttemptedAt: timestamppb.New(now),
	})
	test.AssertNotError(t, err, "sa.FinalizeAuthorization2 failed")

	// Refresh the order so the SA sets its status
	validOrder, err = sa.GetOrder(ctx, &sapb.OrderRequest{
		Id: validOrder.Id,
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

func TestFinalizeOrderDisabledChallenge(t *testing.T) {
	_, sa, ra, _, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	domain := randomDomain()

	// Create a finalized authorization for that domain
	authzID := createFinalizedAuthorization(
		t, sa, domain, fc.Now().Add(24*time.Hour), core.ChallengeTypeHTTP01, fc.Now().Add(-1*time.Hour))

	// Create an order that reuses that authorization
	order, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: Registration.Id,
		DnsNames:       []string{domain},
	})
	test.AssertNotError(t, err, "creating test order")
	test.AssertEquals(t, order.V2Authorizations[0], authzID)

	// Create a CSR for this order
	testKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "generating test key")
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		PublicKey: testKey.PublicKey,
		DNSNames:  []string{domain},
	}, testKey)
	test.AssertNotError(t, err, "Error creating policy forbid CSR")

	// Replace the Policy Authority with one which has this challenge type disabled
	pa, err := policy.New(map[core.AcmeChallenge]bool{
		core.ChallengeTypeDNS01:     true,
		core.ChallengeTypeTLSALPN01: true,
	}, ra.log)
	test.AssertNotError(t, err, "creating test PA")
	err = pa.LoadHostnamePolicyFile("../test/hostname-policy.yaml")
	test.AssertNotError(t, err, "loading test hostname policy")
	ra.PA = pa

	// Now finalizing this order should fail
	_, err = ra.FinalizeOrder(context.Background(), &rapb.FinalizeOrderRequest{
		Order: order,
		Csr:   csr,
	})
	test.AssertError(t, err, "finalization should fail")

	// Unfortunately we can't test for the PA's "which is now disabled" error
	// message directly, because the RA discards it and collects all invalid names
	// into a single more generic error message. But it does at least distinguish
	// between missing, expired, and invalid, so we can test for "invalid".
	test.AssertContains(t, err.Error(), "authorizations for these identifiers not valid")
}

func TestIssueCertificateAuditLog(t *testing.T) {
	_, sa, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Make some valid authorizations for some names using different challenge types
	names := []string{"not-example.com", "www.not-example.com", "still.not-example.com", "definitely.not-example.com"}
	exp := ra.clk.Now().Add(ra.orderLifetime)
	challs := []core.AcmeChallenge{core.ChallengeTypeHTTP01, core.ChallengeTypeDNS01, core.ChallengeTypeHTTP01, core.ChallengeTypeDNS01}
	var authzIDs []int64
	for i, name := range names {
		authzIDs = append(authzIDs, createFinalizedAuthorization(t, sa, name, exp, challs[i], ra.clk.Now()))
	}

	// Create a pending order for all of the names
	order, err := sa.NewOrderAndAuthzs(context.Background(), &sapb.NewOrderAndAuthzsRequest{
		NewOrder: &sapb.NewOrderRequest{
			RegistrationID:   Registration.Id,
			Expires:          timestamppb.New(exp),
			DnsNames:         names,
			V2Authorizations: authzIDs,
		},
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
	order.Status = string(core.StatusReady)
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
	test.AssertEquals(t, event.Requester, Registration.Id)
	// The event order ID should be the expected order ID
	test.AssertEquals(t, event.OrderID, order.Id)
	// The event serial number should be the expected serial number
	test.AssertEquals(t, event.SerialNumber, core.SerialToString(template.SerialNumber))
	// The event verified fields should be the expected value
	test.AssertDeepEquals(t, event.VerifiedFields, []string{"subject.commonName", "subjectAltName"})
	// The event CommonName should match the expected common name
	test.AssertEquals(t, event.CommonName, "not-example.com")
	// The event names should match the order names
	test.AssertDeepEquals(t, core.UniqueLowerNames(event.Names), core.UniqueLowerNames(order.DnsNames))
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
		test.AssertEquals(t, authzEntry.ChallengeType, challs[i])
	}
}

func TestIssueCertificateCAACheckLog(t *testing.T) {
	_, sa, ra, _, fc, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.VA = va.RemoteClients{CAAClient: &noopCAA{}}

	exp := fc.Now().Add(24 * time.Hour)
	recent := fc.Now().Add(-1 * time.Hour)
	older := fc.Now().Add(-8 * time.Hour)

	// Make some valid authzs for four names. Half of them were validated
	// recently and half were validated in excess of our CAA recheck time.
	names := []string{"not-example.com", "www.not-example.com", "still.not-example.com", "definitely.not-example.com"}
	var authzIDs []int64
	for i, name := range names {
		attemptedAt := older
		if i%2 == 0 {
			attemptedAt = recent
		}
		authzIDs = append(authzIDs, createFinalizedAuthorization(t, sa, name, exp, core.ChallengeTypeHTTP01, attemptedAt))
	}

	// Create a pending order for all of the names.
	order, err := sa.NewOrderAndAuthzs(context.Background(), &sapb.NewOrderAndAuthzsRequest{
		NewOrder: &sapb.NewOrderRequest{
			RegistrationID:   Registration.Id,
			Expires:          timestamppb.New(exp),
			DnsNames:         names,
			V2Authorizations: authzIDs,
		},
	})
	test.AssertNotError(t, err, "Could not add test order with finalized authz IDs")

	// Generate a CSR covering the order names with a random RSA key.
	testKey, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "error generating test key")
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		PublicKey:          testKey.PublicKey,
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject:            pkix.Name{CommonName: "not-example.com"},
		DNSNames:           names,
	}, testKey)
	test.AssertNotError(t, err, "Could not create test order CSR")

	// Create a mock certificate for the fake CA to return.
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

	// Set up the RA's CA with a mock that returns the cert from above.
	ra.CA = &mocks.MockCA{
		PEM: pem.EncodeToMemory(&pem.Block{
			Bytes: cert,
		}),
	}

	// Cast the RA's mock log so we can ensure its cleared and can access the
	// matched log lines.
	mockLog := ra.log.(*blog.Mock)
	mockLog.Clear()

	// Finalize the order with the CSR.
	order.Status = string(core.StatusReady)
	_, err = ra.FinalizeOrder(context.Background(), &rapb.FinalizeOrderRequest{
		Order: order,
		Csr:   csr,
	})
	test.AssertNotError(t, err, "Error finalizing test order")

	// Get the logged lines from the mock logger.
	loglines := mockLog.GetAllMatching("FinalizationCaaCheck JSON=")
	// There should be exactly 1 matching log line.
	test.AssertEquals(t, len(loglines), 1)

	// Strip away the stuff before 'JSON='.
	jsonContent := strings.TrimPrefix(loglines[0], "INFO: FinalizationCaaCheck JSON=")

	// Unmarshal the JSON into an event object.
	var event finalizationCAACheckEvent
	err = json.Unmarshal([]byte(jsonContent), &event)
	// The JSON should unmarshal without error.
	test.AssertNotError(t, err, "Error unmarshalling logged JSON issuance event.")
	// The event requester should be the expected registration ID.
	test.AssertEquals(t, event.Requester, Registration.Id)
	// The event should have the expected number of Authzs where CAA was reused.
	test.AssertEquals(t, event.Reused, 2)
	// The event should have the expected number of Authzs where CAA was
	// rechecked.
	test.AssertEquals(t, event.Rechecked, 2)
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
	_, sa, ra, _, fc, cleanUp := initAuthorities(t)
	defer cleanUp()
	ctx := context.Background()

	authzPB := createPendingAuthorization(t, sa, Identifier, fc.Now().Add(12*time.Hour))
	authz, err := bgrpc.PBToAuthz(authzPB)
	test.AssertNotError(t, err, "failed to deserialize authz")

	// Twiddle the authz to pretend its been validated by the VA
	authz.Challenges[0].Status = "valid"
	err = ra.recordValidation(ctx, authz.ID, authz.Expires, &authz.Challenges[0])
	test.AssertNotError(t, err, "ra.recordValidation failed")

	// Try to record the same validation a second time.
	err = ra.recordValidation(ctx, authz.ID, authz.Expires, &authz.Challenges[0])
	test.AssertError(t, err, "ra.recordValidation didn't fail")
	test.AssertErrorIs(t, err, berrors.NotFound)
}

func TestPerformValidationBadChallengeType(t *testing.T) {
	_, _, ra, _, fc, cleanUp := initAuthorities(t)
	defer cleanUp()
	pa, err := policy.New(map[core.AcmeChallenge]bool{}, blog.NewMock())
	test.AssertNotError(t, err, "Couldn't create PA")
	ra.PA = pa

	exp := fc.Now().Add(10 * time.Hour)
	authz := core.Authorization{
		ID:             "1337",
		Identifier:     identifier.NewDNS("not-example.com"),
		RegistrationID: 1,
		Status:         "valid",
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

func (mp *timeoutPub) SubmitToSingleCTWithResult(_ context.Context, _ *pubpb.Request, _ ...grpc.CallOption) (*pubpb.Result, error) {
	return nil, context.DeadlineExceeded
}

func TestCTPolicyMeasurements(t *testing.T) {
	_, ssa, ra, _, _, cleanup := initAuthorities(t)
	defer cleanup()

	ra.ctpolicy = ctpolicy.New(&timeoutPub{}, loglist.List{
		"OperA": {
			"LogA1": {Url: "UrlA1", Key: "KeyA1"},
		},
		"OperB": {
			"LogB1": {Url: "UrlB1", Key: "KeyB1"},
		},
	}, nil, nil, 0, log, metrics.NoopRegisterer)

	// Create valid authorizations for not-example.com and www.not-example.com
	exp := ra.clk.Now().Add(365 * 24 * time.Hour)
	authzIDA := createFinalizedAuthorization(t, ssa, "not-example.com", exp, core.ChallengeTypeHTTP01, ra.clk.Now())
	authzIDB := createFinalizedAuthorization(t, ssa, "www.not-example.com", exp, core.ChallengeTypeHTTP01, ra.clk.Now())

	order, err := ra.SA.NewOrderAndAuthzs(context.Background(), &sapb.NewOrderAndAuthzsRequest{
		NewOrder: &sapb.NewOrderRequest{
			RegistrationID:   Registration.Id,
			Expires:          timestamppb.New(exp),
			DnsNames:         []string{"not-example.com", "www.not-example.com"},
			V2Authorizations: []int64{authzIDA, authzIDB},
		},
	})
	test.AssertNotError(t, err, "error generating test order")

	testKey, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "error generating test key")

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		PublicKey:          testKey.Public(),
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           []string{"not-example.com", "www.not-example.com"},
	}, testKey)
	test.AssertNotError(t, err, "error generating test CSR")

	_, err = ra.FinalizeOrder(context.Background(), &rapb.FinalizeOrderRequest{
		Order: order,
		Csr:   csr,
	})
	test.AssertError(t, err, "FinalizeOrder should have failed when SCTs timed out")
	test.AssertContains(t, err.Error(), "getting SCTs")
	test.AssertMetricWithLabelsEquals(t, ra.ctpolicyResults, prometheus.Labels{"result": "failure"}, 1)
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
	test.AssertErrorIs(t, err, berrors.Malformed)

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
	context.Context,
	*capb.IssueCertificateRequest,
	...grpc.CallOption) (*capb.IssuePrecertificateResponse, error) {
	return nil, ca.err
}

// mockCAFailCertForPrecert is a mock CA that always returns an error from
// `IssueCertificateForPrecertificate`
type mockCAFailCertForPrecert struct {
	mocks.MockCA
	err error
}

// IssuePrecertificate needs to be mocked for mockCAFailCertForPrecert's `IssueCertificateForPrecertificate` to get called.
func (ca *mockCAFailCertForPrecert) IssuePrecertificate(
	ctx context.Context,
	req *capb.IssueCertificateRequest,
	opts ...grpc.CallOption) (*capb.IssuePrecertificateResponse, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	parsedCSR, err := x509.ParseCertificateRequest(req.Csr)
	if err != nil {
		return nil, err
	}
	tmpl := &ctx509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     parsedCSR.DNSNames,
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
	context.Context,
	*capb.IssueCertificateForPrecertificateRequest,
	...grpc.CallOption) (*corepb.Certificate, error) {
	return &corepb.Certificate{}, ca.err
}

// TestIssueCertificateInnerErrs tests that errors from the CA caught during
// `ra.issueCertificateInner` are propagated correctly, with the part of the
// issuance process that failed prefixed on the error message.
func TestIssueCertificateInnerErrs(t *testing.T) {
	_, sa, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// Make some valid authorizations for some names
	names := []string{"not-example.com", "www.not-example.com", "still.not-example.com", "definitely.not-example.com"}
	exp := ra.clk.Now().Add(ra.orderLifetime)
	var authzIDs []int64
	for _, name := range names {
		authzIDs = append(authzIDs, createFinalizedAuthorization(t, sa, name, exp, core.ChallengeTypeHTTP01, ra.clk.Now()))
	}

	// Create a pending order for all of the names
	order, err := sa.NewOrderAndAuthzs(context.Background(), &sapb.NewOrderAndAuthzsRequest{
		NewOrder: &sapb.NewOrderRequest{
			RegistrationID:   Registration.Id,
			Expires:          timestamppb.New(exp),
			DnsNames:         names,
			V2Authorizations: authzIDs,
		},
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

	testCases := []struct {
		Name         string
		Mock         capb.CertificateAuthorityClient
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
			_, _, err = ra.issueCertificateInner(ctx, csrOb, order.CertificateProfileName, accountID(Registration.Id), orderID(order.Id))
			// We expect all of the testcases to fail because all use mocked CAs that deliberately error
			test.AssertError(t, err, "issueCertificateInner with failing mock CA did not fail")
			// If there is an expected `error` then match the error message
			if tc.ExpectedErr != nil {
				test.AssertEquals(t, err.Error(), tc.ExpectedErr.Error())
			} else if tc.ExpectedProb != nil {
				// If there is an expected `berrors.BoulderError` then we expect the
				// `issueCertificateInner` error to be a `berrors.BoulderError`
				var berr *berrors.BoulderError
				test.AssertErrorWraps(t, err, &berr)
				// Match the expected berror Type and Detail to the observed
				test.AssertErrorIs(t, berr, tc.ExpectedProb.Type)
				test.AssertEquals(t, berr.Detail, tc.ExpectedProb.Detail)
			}
		})
	}
}

type MockCARecordingProfile struct {
	inner       *mocks.MockCA
	profileName string
	profileHash []byte
}

func (ca *MockCARecordingProfile) IssuePrecertificate(ctx context.Context, req *capb.IssueCertificateRequest, _ ...grpc.CallOption) (*capb.IssuePrecertificateResponse, error) {
	ca.profileName = req.CertProfileName
	return ca.inner.IssuePrecertificate(ctx, req)
}

func (ca *MockCARecordingProfile) IssueCertificateForPrecertificate(ctx context.Context, req *capb.IssueCertificateForPrecertificateRequest, _ ...grpc.CallOption) (*corepb.Certificate, error) {
	ca.profileHash = req.CertProfileHash
	return ca.inner.IssueCertificateForPrecertificate(ctx, req)
}

type mockSAWithFinalize struct {
	sapb.StorageAuthorityClient
}

func (sa *mockSAWithFinalize) FinalizeOrder(ctx context.Context, req *sapb.FinalizeOrderRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (sa *mockSAWithFinalize) FQDNSetExists(ctx context.Context, in *sapb.FQDNSetExistsRequest, opts ...grpc.CallOption) (*sapb.Exists, error) {
	return &sapb.Exists{}, nil
}

func TestIssueCertificateInnerWithProfile(t *testing.T) {
	_, _, ra, _, fc, cleanup := initAuthorities(t)
	defer cleanup()

	// Generate a reasonable-looking CSR and cert to pass the matchesCSR check.
	testKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "generating test key")
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"example.com"}}, testKey)
	test.AssertNotError(t, err, "creating test csr")
	csr, err := x509.ParseCertificateRequest(csrDER)
	test.AssertNotError(t, err, "parsing test csr")
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		DNSNames:              []string{"example.com"},
		NotBefore:             fc.Now(),
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}, &x509.Certificate{}, testKey.Public(), testKey)
	test.AssertNotError(t, err, "creating test cert")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Use a mock CA that will record the profile name and profile hash included
	// in the RA's request messages. Populate it with the cert generated above.
	mockCA := MockCARecordingProfile{inner: &mocks.MockCA{PEM: certPEM}}
	ra.CA = &mockCA

	ra.SA = &mockSAWithFinalize{}

	// Call issueCertificateInner with the CSR generated above and the profile
	// name "default", which will cause the mockCA to return a specific hash.
	_, cpId, err := ra.issueCertificateInner(context.Background(), csr, "default", 1, 1)
	test.AssertNotError(t, err, "issuing cert with profile name")
	test.AssertEquals(t, mockCA.profileName, cpId.name)
	test.AssertByteEquals(t, mockCA.profileHash, cpId.hash)
}

func TestIssueCertificateOuter(t *testing.T) {
	_, sa, ra, _, fc, cleanup := initAuthorities(t)
	defer cleanup()

	// Make some valid authorizations for some names
	names := []string{"not-example.com", "www.not-example.com", "still.not-example.com", "definitely.not-example.com"}
	exp := ra.clk.Now().Add(ra.orderLifetime)
	var authzIDs []int64
	for _, name := range names {
		authzIDs = append(authzIDs, createFinalizedAuthorization(t, sa, name, exp, core.ChallengeTypeHTTP01, ra.clk.Now()))
	}

	// Create a pending order for all of the names
	order, err := sa.NewOrderAndAuthzs(context.Background(), &sapb.NewOrderAndAuthzsRequest{
		NewOrder: &sapb.NewOrderRequest{
			RegistrationID:         Registration.Id,
			Expires:                timestamppb.New(exp),
			DnsNames:               names,
			V2Authorizations:       authzIDs,
			CertificateProfileName: "philsProfile",
		},
	})
	test.AssertNotError(t, err, "Could not add test order with finalized authz IDs")

	testKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "generating test key")
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"example.com"}}, testKey)
	test.AssertNotError(t, err, "creating test csr")
	csr, err := x509.ParseCertificateRequest(csrDER)
	test.AssertNotError(t, err, "parsing test csr")
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		DNSNames:              []string{"example.com"},
		NotBefore:             fc.Now(),
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}, &x509.Certificate{}, testKey.Public(), testKey)
	test.AssertNotError(t, err, "creating test cert")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Use a mock CA that will record the profile name and profile hash included
	// in the RA's request messages. Populate it with the cert generated above.
	mockCA := MockCARecordingProfile{inner: &mocks.MockCA{PEM: certPEM}}
	ra.CA = &mockCA

	ra.SA = &mockSAWithFinalize{}

	_, err = ra.issueCertificateOuter(context.Background(), order, csr, certificateRequestEvent{})
	test.AssertNotError(t, err, "Could not issue certificate")
	test.AssertMetricWithLabelsEquals(t, ra.newCertCounter, prometheus.Labels{"profileName": mockCA.profileName, "profileHash": fmt.Sprintf("%x", mockCA.profileHash)}, 1)
}

func TestNewOrderMaxNames(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	ra.maxNames = 2
	_, err := ra.NewOrder(context.Background(), &rapb.NewOrderRequest{
		RegistrationID: 1,
		DnsNames: []string{
			"a",
			"b",
			"c",
		},
	})
	test.AssertError(t, err, "NewOrder didn't fail with too many names in request")
	test.AssertEquals(t, err.Error(), "Order cannot contain more than 2 DNS names")
	test.AssertErrorIs(t, err, berrors.Malformed)
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

// mockSARevocation is a fake which includes all of the SA methods called in the
// course of a revocation. Its behavior can be customized by providing sets of
// issued (known) certs, already-revoked certs, and already-blocked keys. It
// also updates the sets of revoked certs and blocked keys when certain methods
// are called, to allow for more complex test logic.
type mockSARevocation struct {
	sapb.StorageAuthorityClient

	known   map[string]*x509.Certificate
	revoked map[string]*corepb.CertificateStatus
	blocked []*sapb.AddBlockedKeyRequest
}

func newMockSARevocation(known *x509.Certificate) *mockSARevocation {
	return &mockSARevocation{
		known:   map[string]*x509.Certificate{core.SerialToString(known.SerialNumber): known},
		revoked: make(map[string]*corepb.CertificateStatus),
		blocked: make([]*sapb.AddBlockedKeyRequest, 0),
	}
}

func (msar *mockSARevocation) reset() {
	msar.revoked = make(map[string]*corepb.CertificateStatus)
	msar.blocked = make([]*sapb.AddBlockedKeyRequest, 0)
}

func (msar *mockSARevocation) AddBlockedKey(_ context.Context, req *sapb.AddBlockedKeyRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	msar.blocked = append(msar.blocked, req)
	return &emptypb.Empty{}, nil
}

func (msar *mockSARevocation) GetSerialMetadata(_ context.Context, req *sapb.Serial, _ ...grpc.CallOption) (*sapb.SerialMetadata, error) {
	if cert, present := msar.known[req.Serial]; present {
		return &sapb.SerialMetadata{
			Serial:         req.Serial,
			RegistrationID: 1,
			Created:        timestamppb.New(cert.NotBefore),
			Expires:        timestamppb.New(cert.NotAfter),
		}, nil
	}
	return nil, berrors.UnknownSerialError()
}

func (msar *mockSARevocation) GetLintPrecertificate(_ context.Context, req *sapb.Serial, _ ...grpc.CallOption) (*corepb.Certificate, error) {
	if cert, present := msar.known[req.Serial]; present {
		return &corepb.Certificate{Der: cert.Raw}, nil
	}
	return nil, berrors.UnknownSerialError()
}

func (msar *mockSARevocation) GetCertificateStatus(_ context.Context, req *sapb.Serial, _ ...grpc.CallOption) (*corepb.CertificateStatus, error) {
	if status, present := msar.revoked[req.Serial]; present {
		return status, nil
	}
	if cert, present := msar.known[req.Serial]; present {
		return &corepb.CertificateStatus{
			Serial:   core.SerialToString(cert.SerialNumber),
			IssuerID: int64(issuance.IssuerNameID(cert)),
		}, nil
	}
	return nil, berrors.UnknownSerialError()
}

func (msar *mockSARevocation) RevokeCertificate(_ context.Context, req *sapb.RevokeCertificateRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	if _, present := msar.revoked[req.Serial]; present {
		return nil, berrors.AlreadyRevokedError("already revoked")
	}
	cert, present := msar.known[req.Serial]
	if !present {
		return nil, berrors.UnknownSerialError()
	}
	msar.revoked[req.Serial] = &corepb.CertificateStatus{
		Serial:        req.Serial,
		IssuerID:      int64(issuance.IssuerNameID(cert)),
		Status:        string(core.OCSPStatusRevoked),
		RevokedReason: req.Reason,
	}
	return &emptypb.Empty{}, nil
}

func (msar *mockSARevocation) UpdateRevokedCertificate(_ context.Context, req *sapb.RevokeCertificateRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	status, present := msar.revoked[req.Serial]
	if !present {
		return nil, errors.New("not already revoked")
	}
	if req.Reason != ocsp.KeyCompromise {
		return nil, errors.New("cannot re-revoke except for keyCompromise")
	}
	if present && status.RevokedReason == ocsp.KeyCompromise {
		return nil, berrors.AlreadyRevokedError("already revoked for keyCompromise")
	}
	msar.revoked[req.Serial].RevokedReason = req.Reason
	return &emptypb.Empty{}, nil
}

type mockOCSPA struct {
	mocks.MockCA
}

func (mcao *mockOCSPA) GenerateOCSP(context.Context, *capb.GenerateOCSPRequest, ...grpc.CallOption) (*capb.OCSPResponse, error) {
	return &capb.OCSPResponse{Response: []byte{1, 2, 3}}, nil
}

type mockPurger struct{}

func (mp *mockPurger) Purge(context.Context, *akamaipb.PurgeRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

// mockSAGenerateOCSP is a mock SA that always returns a good OCSP response, with a constant NotAfter.
type mockSAGenerateOCSP struct {
	sapb.StorageAuthorityClient
	expiration time.Time
}

func (msgo *mockSAGenerateOCSP) GetCertificateStatus(_ context.Context, req *sapb.Serial, _ ...grpc.CallOption) (*corepb.CertificateStatus, error) {
	return &corepb.CertificateStatus{
		Serial:   req.Serial,
		Status:   "good",
		NotAfter: timestamppb.New(msgo.expiration.UTC()),
	}, nil
}

func TestGenerateOCSP(t *testing.T) {
	_, _, ra, _, clk, cleanUp := initAuthorities(t)
	defer cleanUp()

	ra.OCSP = &mockOCSPA{}
	ra.SA = &mockSAGenerateOCSP{expiration: clk.Now().Add(time.Hour)}

	req := &rapb.GenerateOCSPRequest{
		Serial: core.SerialToString(big.NewInt(1)),
	}

	resp, err := ra.GenerateOCSP(context.Background(), req)
	test.AssertNotError(t, err, "generating OCSP")
	test.AssertByteEquals(t, resp.Response, []byte{1, 2, 3})

	ra.SA = &mockSAGenerateOCSP{expiration: clk.Now().Add(-time.Hour)}
	_, err = ra.GenerateOCSP(context.Background(), req)
	if !errors.Is(err, berrors.NotFound) {
		t.Errorf("expected NotFound error, got %s", err)
	}
}

// mockSALongExpiredSerial is a mock SA that treats every serial as if it expired a long time ago.
// Specifically, it returns NotFound to GetCertificateStatus (simulating the serial having been
// removed from the certificateStatus table), but returns success to GetSerialMetadata (simulating
// a serial number staying in the `serials` table indefinitely).
type mockSALongExpiredSerial struct {
	sapb.StorageAuthorityClient
}

func (msgo *mockSALongExpiredSerial) GetCertificateStatus(_ context.Context, req *sapb.Serial, _ ...grpc.CallOption) (*corepb.CertificateStatus, error) {
	return nil, berrors.NotFoundError("not found")
}

func (msgo *mockSALongExpiredSerial) GetSerialMetadata(_ context.Context, req *sapb.Serial, _ ...grpc.CallOption) (*sapb.SerialMetadata, error) {
	return &sapb.SerialMetadata{
		Serial: req.Serial,
	}, nil
}

func TestGenerateOCSPLongExpiredSerial(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	ra.OCSP = &mockOCSPA{}
	ra.SA = &mockSALongExpiredSerial{}

	req := &rapb.GenerateOCSPRequest{
		Serial: core.SerialToString(big.NewInt(1)),
	}

	_, err := ra.GenerateOCSP(context.Background(), req)
	test.AssertError(t, err, "generating OCSP")
	if !errors.Is(err, berrors.NotFound) {
		t.Errorf("expected NotFound error, got %#v", err)
	}
}

// mockSAUnknownSerial is a mock SA that always returns NotFound to certificate status and serial lookups.
// It emulates an SA that has never issued a certificate.
type mockSAUnknownSerial struct {
	mockSALongExpiredSerial
}

func (msgo *mockSAUnknownSerial) GetSerialMetadata(_ context.Context, req *sapb.Serial, _ ...grpc.CallOption) (*sapb.SerialMetadata, error) {
	return nil, berrors.NotFoundError("not found")
}

func TestGenerateOCSPUnknownSerial(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	ra.OCSP = &mockOCSPA{}
	ra.SA = &mockSAUnknownSerial{}

	req := &rapb.GenerateOCSPRequest{
		Serial: core.SerialToString(big.NewInt(1)),
	}

	_, err := ra.GenerateOCSP(context.Background(), req)
	test.AssertError(t, err, "generating OCSP")
	if !errors.Is(err, berrors.UnknownSerial) {
		t.Errorf("expected UnknownSerial error, got %#v", err)
	}
}

func TestRevokeCertByApplicant_Subscriber(t *testing.T) {
	_, _, ra, _, clk, cleanUp := initAuthorities(t)
	defer cleanUp()

	ra.OCSP = &mockOCSPA{}
	ra.purger = &mockPurger{}

	// Use the same self-signed cert as both issuer and issuee for revocation.
	_, cert := test.ThrowAwayCert(t, clk)
	cert.IsCA = true
	ic, err := issuance.NewCertificate(cert)
	test.AssertNotError(t, err, "failed to create issuer cert")
	ra.issuersByNameID = map[issuance.NameID]*issuance.Certificate{
		ic.NameID(): ic,
	}
	ra.SA = newMockSARevocation(cert)

	// Revoking without a regID should fail.
	_, err = ra.RevokeCertByApplicant(context.Background(), &rapb.RevokeCertByApplicantRequest{
		Cert:  cert.Raw,
		Code:  ocsp.Unspecified,
		RegID: 0,
	})
	test.AssertError(t, err, "should have failed with no RegID")
	test.AssertContains(t, err.Error(), "incomplete")

	// Revoking for a disallowed reason should fail.
	_, err = ra.RevokeCertByApplicant(context.Background(), &rapb.RevokeCertByApplicantRequest{
		Cert:  cert.Raw,
		Code:  ocsp.CertificateHold,
		RegID: 1,
	})
	test.AssertError(t, err, "should have failed with bad reasonCode")
	test.AssertContains(t, err.Error(), "disallowed revocation reason")

	// Revoking with the correct regID should succeed.
	_, err = ra.RevokeCertByApplicant(context.Background(), &rapb.RevokeCertByApplicantRequest{
		Cert:  cert.Raw,
		Code:  ocsp.Unspecified,
		RegID: 1,
	})
	test.AssertNotError(t, err, "should have succeeded")

	// Revoking an already-revoked serial should fail.
	_, err = ra.RevokeCertByApplicant(context.Background(), &rapb.RevokeCertByApplicantRequest{
		Cert:  cert.Raw,
		Code:  ocsp.Unspecified,
		RegID: 1,
	})
	test.AssertError(t, err, "should have failed with bad reasonCode")
	test.AssertContains(t, err.Error(), "already revoked")
}

// mockSARevocationWithAuthzs embeds a mockSARevocation and so inherits all its
// methods, but also adds GetValidAuthorizations2 so that it can pretend to
// either be authorized or not for all of the names in the to-be-revoked cert.
type mockSARevocationWithAuthzs struct {
	*mockSARevocation
	authorized bool
}

func (msa *mockSARevocationWithAuthzs) GetValidAuthorizations2(ctx context.Context, req *sapb.GetValidAuthorizationsRequest, _ ...grpc.CallOption) (*sapb.Authorizations, error) {
	authzs := &sapb.Authorizations{}

	if !msa.authorized {
		return authzs, nil
	}

	for _, name := range req.DnsNames {
		authzs.Authzs = append(authzs.Authzs, &corepb.Authorization{DnsName: name})
	}

	return authzs, nil
}

func TestRevokeCertByApplicant_Controller(t *testing.T) {
	_, _, ra, _, clk, cleanUp := initAuthorities(t)
	defer cleanUp()

	ra.OCSP = &mockOCSPA{}
	ra.purger = &mockPurger{}

	// Use the same self-signed cert as both issuer and issuee for revocation.
	_, cert := test.ThrowAwayCert(t, clk)
	cert.IsCA = true
	ic, err := issuance.NewCertificate(cert)
	test.AssertNotError(t, err, "failed to create issuer cert")
	ra.issuersByNameID = map[issuance.NameID]*issuance.Certificate{
		ic.NameID(): ic,
	}
	mockSA := newMockSARevocation(cert)

	// Revoking when the account doesn't have valid authzs for the name should fail.
	// We use RegID 2 here and below because the mockSARevocation believes regID 1
	// is the original issuer.
	ra.SA = &mockSARevocationWithAuthzs{mockSA, false}
	_, err = ra.RevokeCertByApplicant(context.Background(), &rapb.RevokeCertByApplicantRequest{
		Cert:  cert.Raw,
		Code:  ocsp.Unspecified,
		RegID: 2,
	})
	test.AssertError(t, err, "should have failed with wrong RegID")
	test.AssertContains(t, err.Error(), "requester does not control all names")

	// Revoking when the account does have valid authzs for the name should succeed,
	// but override the revocation reason to cessationOfOperation.
	ra.SA = &mockSARevocationWithAuthzs{mockSA, true}
	_, err = ra.RevokeCertByApplicant(context.Background(), &rapb.RevokeCertByApplicantRequest{
		Cert:  cert.Raw,
		Code:  ocsp.Unspecified,
		RegID: 2,
	})
	test.AssertNotError(t, err, "should have succeeded")
	test.AssertEquals(t, mockSA.revoked[core.SerialToString(cert.SerialNumber)].RevokedReason, int64(ocsp.CessationOfOperation))
}

func TestRevokeCertByKey(t *testing.T) {
	_, _, ra, _, clk, cleanUp := initAuthorities(t)
	defer cleanUp()

	ra.OCSP = &mockOCSPA{}
	ra.purger = &mockPurger{}

	// Use the same self-signed cert as both issuer and issuee for revocation.
	_, cert := test.ThrowAwayCert(t, clk)
	digest, err := core.KeyDigest(cert.PublicKey)
	test.AssertNotError(t, err, "core.KeyDigest failed")
	cert.IsCA = true
	ic, err := issuance.NewCertificate(cert)
	test.AssertNotError(t, err, "failed to create issuer cert")
	ra.issuersByNameID = map[issuance.NameID]*issuance.Certificate{
		ic.NameID(): ic,
	}
	mockSA := newMockSARevocation(cert)
	ra.SA = mockSA

	// Revoking should work, but override the requested reason and block the key.
	_, err = ra.RevokeCertByKey(context.Background(), &rapb.RevokeCertByKeyRequest{
		Cert: cert.Raw,
	})
	test.AssertNotError(t, err, "should have succeeded")
	test.AssertEquals(t, len(mockSA.blocked), 1)
	test.Assert(t, bytes.Equal(digest[:], mockSA.blocked[0].KeyHash), "key hash mismatch")
	test.AssertEquals(t, mockSA.blocked[0].Source, "API")
	test.AssertEquals(t, len(mockSA.blocked[0].Comment), 0)
	test.AssertEquals(t, mockSA.revoked[core.SerialToString(cert.SerialNumber)].RevokedReason, int64(ocsp.KeyCompromise))

	// Re-revoking should fail, because it is already revoked for keyCompromise.
	_, err = ra.RevokeCertByKey(context.Background(), &rapb.RevokeCertByKeyRequest{
		Cert: cert.Raw,
	})
	test.AssertError(t, err, "should have failed")

	// Reset and have the Subscriber revoke for a different reason.
	// Then re-revoking using the key should work.
	mockSA.revoked = make(map[string]*corepb.CertificateStatus)
	_, err = ra.RevokeCertByApplicant(context.Background(), &rapb.RevokeCertByApplicantRequest{
		Cert:  cert.Raw,
		Code:  ocsp.Unspecified,
		RegID: 1,
	})
	test.AssertNotError(t, err, "should have succeeded")
	_, err = ra.RevokeCertByKey(context.Background(), &rapb.RevokeCertByKeyRequest{
		Cert: cert.Raw,
	})
	test.AssertNotError(t, err, "should have succeeded")
}

func TestAdministrativelyRevokeCertificate(t *testing.T) {
	_, _, ra, _, clk, cleanUp := initAuthorities(t)
	defer cleanUp()

	ra.OCSP = &mockOCSPA{}
	ra.purger = &mockPurger{}

	// Use the same self-signed cert as both issuer and issuee for revocation.
	serial, cert := test.ThrowAwayCert(t, clk)
	digest, err := core.KeyDigest(cert.PublicKey)
	test.AssertNotError(t, err, "core.KeyDigest failed")
	cert.IsCA = true
	ic, err := issuance.NewCertificate(cert)
	test.AssertNotError(t, err, "failed to create issuer cert")
	ra.issuersByNameID = map[issuance.NameID]*issuance.Certificate{
		ic.NameID(): ic,
	}
	mockSA := newMockSARevocation(cert)
	ra.SA = mockSA

	// Revoking with an empty request should fail immediately.
	_, err = ra.AdministrativelyRevokeCertificate(context.Background(), &rapb.AdministrativelyRevokeCertificateRequest{})
	test.AssertError(t, err, "AdministrativelyRevokeCertificate should have failed for nil request object")

	// Revoking with no serial should fail immediately.
	mockSA.reset()
	_, err = ra.AdministrativelyRevokeCertificate(context.Background(), &rapb.AdministrativelyRevokeCertificateRequest{
		Code:      ocsp.Unspecified,
		AdminName: "root",
	})
	test.AssertError(t, err, "AdministrativelyRevokeCertificate should have failed with no cert or serial")

	// Revoking without an admin name should fail immediately.
	mockSA.reset()
	_, err = ra.AdministrativelyRevokeCertificate(context.Background(), &rapb.AdministrativelyRevokeCertificateRequest{
		Serial:    serial,
		Code:      ocsp.Unspecified,
		AdminName: "",
	})
	test.AssertError(t, err, "AdministrativelyRevokeCertificate should have failed with empty string for `AdminName`")

	// Revoking for a forbidden reason should fail immediately.
	mockSA.reset()
	_, err = ra.AdministrativelyRevokeCertificate(context.Background(), &rapb.AdministrativelyRevokeCertificateRequest{
		Serial:    serial,
		Code:      ocsp.CertificateHold,
		AdminName: "root",
	})
	test.AssertError(t, err, "AdministrativelyRevokeCertificate should have failed with forbidden revocation reason")

	// Revoking a cert for an unspecified reason should work but not block the key.
	mockSA.reset()
	_, err = ra.AdministrativelyRevokeCertificate(context.Background(), &rapb.AdministrativelyRevokeCertificateRequest{
		Serial:    serial,
		Code:      ocsp.Unspecified,
		AdminName: "root",
	})
	test.AssertNotError(t, err, "AdministrativelyRevokeCertificate failed")
	test.AssertEquals(t, len(mockSA.blocked), 0)
	test.AssertMetricWithLabelsEquals(
		t, ra.revocationReasonCounter, prometheus.Labels{"reason": "unspecified"}, 1)

	// Revoking a serial for an unspecified reason should work but not block the key.
	mockSA.reset()
	_, err = ra.AdministrativelyRevokeCertificate(context.Background(), &rapb.AdministrativelyRevokeCertificateRequest{
		Serial:    serial,
		Code:      ocsp.Unspecified,
		AdminName: "root",
	})
	test.AssertNotError(t, err, "AdministrativelyRevokeCertificate failed")
	test.AssertEquals(t, len(mockSA.blocked), 0)
	test.AssertMetricWithLabelsEquals(
		t, ra.revocationReasonCounter, prometheus.Labels{"reason": "unspecified"}, 2)

	// Duplicate administrative revocation of a serial for an unspecified reason
	// should succeed because the akamai cache purge succeeds.
	// Note that we *don't* call reset() here, so it recognizes the duplicate.
	_, err = ra.AdministrativelyRevokeCertificate(context.Background(), &rapb.AdministrativelyRevokeCertificateRequest{
		Serial:    serial,
		Code:      ocsp.Unspecified,
		AdminName: "root",
	})
	test.AssertNotError(t, err, "AdministrativelyRevokeCertificate failed")
	test.AssertEquals(t, len(mockSA.blocked), 0)
	test.AssertMetricWithLabelsEquals(
		t, ra.revocationReasonCounter, prometheus.Labels{"reason": "unspecified"}, 2)

	// Duplicate administrative revocation of a serial for a *malformed* cert for
	// an unspecified reason should fail because we can't attempt an akamai cache
	// purge so the underlying AlreadyRevoked error gets propagated upwards.
	// Note that we *don't* call reset() here, so it recognizes the duplicate.
	_, err = ra.AdministrativelyRevokeCertificate(context.Background(), &rapb.AdministrativelyRevokeCertificateRequest{
		Serial:    serial,
		Code:      ocsp.Unspecified,
		AdminName: "root",
		Malformed: true,
	})
	test.AssertError(t, err, "Should be revoked")
	test.AssertContains(t, err.Error(), "already revoked")
	test.AssertEquals(t, len(mockSA.blocked), 0)
	test.AssertMetricWithLabelsEquals(
		t, ra.revocationReasonCounter, prometheus.Labels{"reason": "unspecified"}, 2)

	// Revoking a cert for key compromise with skipBlockKey set should work but
	// not block the key.
	mockSA.reset()
	_, err = ra.AdministrativelyRevokeCertificate(context.Background(), &rapb.AdministrativelyRevokeCertificateRequest{
		Serial:       serial,
		Code:         ocsp.KeyCompromise,
		AdminName:    "root",
		SkipBlockKey: true,
	})
	test.AssertNotError(t, err, "AdministrativelyRevokeCertificate failed")
	test.AssertEquals(t, len(mockSA.blocked), 0)
	test.AssertMetricWithLabelsEquals(
		t, ra.revocationReasonCounter, prometheus.Labels{"reason": "keyCompromise"}, 1)

	// Revoking a cert for key compromise should work and block the key.
	mockSA.reset()
	_, err = ra.AdministrativelyRevokeCertificate(context.Background(), &rapb.AdministrativelyRevokeCertificateRequest{
		Serial:    serial,
		Code:      ocsp.KeyCompromise,
		AdminName: "root",
	})
	test.AssertNotError(t, err, "AdministrativelyRevokeCertificate failed")
	test.AssertEquals(t, len(mockSA.blocked), 1)
	test.Assert(t, bytes.Equal(digest[:], mockSA.blocked[0].KeyHash), "key hash mismatch")
	test.AssertEquals(t, mockSA.blocked[0].Source, "admin-revoker")
	test.AssertEquals(t, mockSA.blocked[0].Comment, "revoked by root")
	test.AssertEquals(t, mockSA.blocked[0].Added.AsTime(), clk.Now())
	test.AssertMetricWithLabelsEquals(
		t, ra.revocationReasonCounter, prometheus.Labels{"reason": "keyCompromise"}, 2)

	// Revoking a malformed cert for key compromise should fail because we don't
	// have the pubkey to block.
	mockSA.reset()
	_, err = ra.AdministrativelyRevokeCertificate(context.Background(), &rapb.AdministrativelyRevokeCertificateRequest{
		Serial:    core.SerialToString(cert.SerialNumber),
		Code:      ocsp.KeyCompromise,
		AdminName: "root",
		Malformed: true,
	})
	test.AssertError(t, err, "AdministrativelyRevokeCertificate should have failed with just serial for keyCompromise")
}

// An authority that returns an error from NewOrderAndAuthzs if the
// "ReplacesSerial" field of the request is empty.
type mockNewOrderMustBeReplacementAuthority struct {
	mockSAWithAuthzs
}

func (sa *mockNewOrderMustBeReplacementAuthority) NewOrderAndAuthzs(ctx context.Context, req *sapb.NewOrderAndAuthzsRequest, _ ...grpc.CallOption) (*corepb.Order, error) {
	if req.NewOrder.ReplacesSerial == "" {
		return nil, status.Error(codes.InvalidArgument, "NewOrder is not a replacement")
	}
	return &corepb.Order{
		Id:             1,
		RegistrationID: req.NewOrder.RegistrationID,
		Expires:        req.NewOrder.Expires,
		Status:         string(core.StatusPending),
		Created:        timestamppb.New(time.Now()),
		DnsNames:       req.NewOrder.DnsNames,
	}, nil
}

func TestNewOrderReplacesSerialCarriesThroughToSA(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	exampleOrder := &rapb.NewOrderRequest{
		RegistrationID: Registration.Id,
		DnsNames:       []string{"example.com"},
		ReplacesSerial: "1234",
	}

	// Mock SA that returns an error from NewOrderAndAuthzs if the
	// "ReplacesSerial" field of the request is empty.
	ra.SA = &mockNewOrderMustBeReplacementAuthority{mockSAWithAuthzs{}}

	_, err := ra.NewOrder(ctx, exampleOrder)
	test.AssertNotError(t, err, "order with ReplacesSerial should have succeeded")
}

// newMockSAUnpauseAccount is a fake which includes all of the SA methods called
// in the course of an account unpause. Its behavior can be customized by
// providing the number of unpaused account identifiers to allow testing of
// various scenarios.
type mockSAUnpauseAccount struct {
	sapb.StorageAuthorityClient
	identsToUnpause int64
	receivedRegID   int64
}

func (sa *mockSAUnpauseAccount) UnpauseAccount(_ context.Context, req *sapb.RegistrationID, _ ...grpc.CallOption) (*sapb.Count, error) {
	sa.receivedRegID = req.Id
	return &sapb.Count{Count: sa.identsToUnpause}, nil
}

// TestUnpauseAccount tests that the RA's UnpauseAccount method correctly passes
// the requested RegID to the SA, and correctly passes the SA's count back to
// the caller.
func TestUnpauseAccount(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	mockSA := mockSAUnpauseAccount{identsToUnpause: 0}
	ra.SA = &mockSA

	res, err := ra.UnpauseAccount(context.Background(), &rapb.UnpauseAccountRequest{
		RegistrationID: 1,
	})
	test.AssertNotError(t, err, "Should have been able to unpause account")
	test.AssertEquals(t, res.Count, int64(0))
	test.AssertEquals(t, mockSA.receivedRegID, int64(1))

	mockSA.identsToUnpause = 50001
	res, err = ra.UnpauseAccount(context.Background(), &rapb.UnpauseAccountRequest{
		RegistrationID: 1,
	})
	test.AssertNotError(t, err, "Should have been able to unpause account")
	test.AssertEquals(t, res.Count, int64(50001))
}

func TestGetAuthorization(t *testing.T) {
	_, _, ra, _, _, cleanup := initAuthorities(t)
	defer cleanup()

	ra.SA = &mockSAWithAuthzs{
		authzs: []*core.Authorization{
			{
				ID:         "1",
				Identifier: identifier.NewDNS("example.com"),
				Status:     "valid",
				Challenges: []core.Challenge{
					{
						Type:   core.ChallengeTypeHTTP01,
						Status: core.StatusValid,
					},
				},
			},
		},
	}

	// With HTTP01 enabled, GetAuthorization should pass the mock challenge through.
	pa, err := policy.New(map[core.AcmeChallenge]bool{
		core.ChallengeTypeHTTP01: true,
		core.ChallengeTypeDNS01:  true,
	}, blog.NewMock())
	test.AssertNotError(t, err, "Couldn't create PA")
	ra.PA = pa
	authz, err := ra.GetAuthorization(context.Background(), &rapb.GetAuthorizationRequest{Id: 1})
	test.AssertNotError(t, err, "should not fail")
	test.AssertEquals(t, len(authz.Challenges), 1)
	test.AssertEquals(t, authz.Challenges[0].Type, string(core.ChallengeTypeHTTP01))

	// With HTTP01 disabled, GetAuthorization should filter out the mock challenge.
	pa, err = policy.New(map[core.AcmeChallenge]bool{
		core.ChallengeTypeDNS01: true,
	}, blog.NewMock())
	test.AssertNotError(t, err, "Couldn't create PA")
	ra.PA = pa
	authz, err = ra.GetAuthorization(context.Background(), &rapb.GetAuthorizationRequest{Id: 1})
	test.AssertNotError(t, err, "should not fail")
	test.AssertEquals(t, len(authz.Challenges), 0)
}

// mockSARecordingRegistration tests UpdateRegistrationContact and UpdateRegistrationKey.
type mockSARecordingRegistration struct {
	sapb.StorageAuthorityClient
	providedRegistrationID int64
	providedContacts       []string
	providedJwk            []byte
}

// UpdateRegistrationContact records the registration ID and updated contacts
// (optional) provided.
func (sa *mockSARecordingRegistration) UpdateRegistrationContact(ctx context.Context, req *sapb.UpdateRegistrationContactRequest, _ ...grpc.CallOption) (*corepb.Registration, error) {
	sa.providedRegistrationID = req.RegistrationID
	sa.providedContacts = req.Contacts

	return &corepb.Registration{
		Id:      req.RegistrationID,
		Contact: req.Contacts,
	}, nil
}

// UpdateRegistrationKey records the registration ID and updated key provided.
func (sa *mockSARecordingRegistration) UpdateRegistrationKey(ctx context.Context, req *sapb.UpdateRegistrationKeyRequest, _ ...grpc.CallOption) (*corepb.Registration, error) {
	sa.providedRegistrationID = req.RegistrationID
	sa.providedJwk = req.Jwk

	return &corepb.Registration{
		Id:  req.RegistrationID,
		Key: req.Jwk,
	}, nil
}

// TestUpdateRegistrationContact tests that the RA's UpdateRegistrationContact
// method correctly: requires a registration ID; validates the contact provided;
// does not require a contact; passes the requested registration ID and contact
// to the SA; passes the updated Registration back to the caller; and can return
// an error.
func TestUpdateRegistrationContact(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	expectRegID := int64(1)
	expectContacts := []string{"mailto:test@contoso.com"}
	mockSA := mockSARecordingRegistration{}
	ra.SA = &mockSA

	_, err := ra.UpdateRegistrationContact(context.Background(), &rapb.UpdateRegistrationContactRequest{})
	test.AssertError(t, err, "should not have been able to update registration contact without a registration ID")
	test.AssertContains(t, err.Error(), "incomplete gRPC request message")

	_, err = ra.UpdateRegistrationContact(context.Background(), &rapb.UpdateRegistrationContactRequest{
		RegistrationID: expectRegID,
		Contacts:       []string{"tel:+44123"},
	})
	test.AssertError(t, err, "should not have been able to update registration contact to an invalid contact")
	test.AssertContains(t, err.Error(), "invalid contact")

	res, err := ra.UpdateRegistrationContact(context.Background(), &rapb.UpdateRegistrationContactRequest{
		RegistrationID: expectRegID,
	})
	test.AssertNotError(t, err, "should have been able to update registration with a blank contact")
	test.AssertEquals(t, res.Id, expectRegID)
	test.AssertEquals(t, mockSA.providedRegistrationID, expectRegID)
	test.AssertDeepEquals(t, res.Contact, []string(nil))
	test.AssertDeepEquals(t, mockSA.providedContacts, []string(nil))

	res, err = ra.UpdateRegistrationContact(context.Background(), &rapb.UpdateRegistrationContactRequest{
		RegistrationID: expectRegID,
		Contacts:       expectContacts,
	})
	test.AssertNotError(t, err, "should have been able to update registration with a populated contact")
	test.AssertEquals(t, res.Id, expectRegID)
	test.AssertEquals(t, mockSA.providedRegistrationID, expectRegID)
	test.AssertDeepEquals(t, res.Contact, expectContacts)
	test.AssertDeepEquals(t, mockSA.providedContacts, expectContacts)

	// Switch to a mock SA that will always error if UpdateRegistrationContact()
	// is called.
	ra.SA = &NoUpdateSA{}
	_, err = ra.UpdateRegistrationContact(context.Background(), &rapb.UpdateRegistrationContactRequest{
		RegistrationID: expectRegID,
		Contacts:       expectContacts,
	})
	test.AssertError(t, err, "should have received an error from the SA")
	test.AssertContains(t, err.Error(), "failed to update registration contact")
	test.AssertContains(t, err.Error(), "mocked to always error")
}

// TestUpdateRegistrationKey tests that the RA's UpdateRegistrationKey method
// correctly requires a registration ID and key, passes them to the SA, and
// passes the updated Registration back to the caller.
func TestUpdateRegistrationKey(t *testing.T) {
	_, _, ra, _, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	expectRegID := int64(1)
	expectJwk := AccountKeyJSONA
	mockSA := mockSARecordingRegistration{}
	ra.SA = &mockSA

	_, err := ra.UpdateRegistrationKey(context.Background(), &rapb.UpdateRegistrationKeyRequest{})
	test.AssertError(t, err, "should not have been able to update registration key without a registration ID or key")
	test.AssertContains(t, err.Error(), "incomplete gRPC request message")

	_, err = ra.UpdateRegistrationKey(context.Background(), &rapb.UpdateRegistrationKeyRequest{RegistrationID: expectRegID})
	test.AssertError(t, err, "should not have been able to update registration key without a key")
	test.AssertContains(t, err.Error(), "incomplete gRPC request message")

	_, err = ra.UpdateRegistrationKey(context.Background(), &rapb.UpdateRegistrationKeyRequest{Jwk: expectJwk})
	test.AssertError(t, err, "should not have been able to update registration key without a registration ID")
	test.AssertContains(t, err.Error(), "incomplete gRPC request message")

	res, err := ra.UpdateRegistrationKey(context.Background(), &rapb.UpdateRegistrationKeyRequest{
		RegistrationID: expectRegID,
		Jwk:            expectJwk,
	})
	test.AssertNotError(t, err, "should have been able to update registration key")
	test.AssertEquals(t, res.Id, expectRegID)
	test.AssertEquals(t, mockSA.providedRegistrationID, expectRegID)
	test.AssertDeepEquals(t, res.Key, expectJwk)
	test.AssertDeepEquals(t, mockSA.providedJwk, expectJwk)

	// Switch to a mock SA that will always error if UpdateRegistrationKey() is
	// called.
	ra.SA = &NoUpdateSA{}
	_, err = ra.UpdateRegistrationKey(context.Background(), &rapb.UpdateRegistrationKeyRequest{
		RegistrationID: expectRegID,
		Jwk:            expectJwk,
	})
	test.AssertError(t, err, "should have received an error from the SA")
	test.AssertContains(t, err.Error(), "failed to update registration key")
	test.AssertContains(t, err.Error(), "mocked to always error")
}
