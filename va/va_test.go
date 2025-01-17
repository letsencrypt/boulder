package va

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/identifier"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"
	vapb "github.com/letsencrypt/boulder/va/proto"
)

var expectedToken = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
var expectedThumbprint = "9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI"
var expectedKeyAuthorization = ka(expectedToken)

func ka(token string) string {
	return token + "." + expectedThumbprint
}

func bigIntFromB64(b64 string) *big.Int {
	bytes, _ := base64.URLEncoding.DecodeString(b64)
	x := big.NewInt(0)
	x.SetBytes(bytes)
	return x
}

func intFromB64(b64 string) int {
	return int(bigIntFromB64(b64).Int64())
}

var n = bigIntFromB64("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw==")
var e = intFromB64("AQAB")
var d = bigIntFromB64("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ==")
var p = bigIntFromB64("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc=")
var q = bigIntFromB64("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc=")

var TheKey = rsa.PrivateKey{
	PublicKey: rsa.PublicKey{N: n, E: e},
	D:         d,
	Primes:    []*big.Int{p, q},
}

var accountKey = &jose.JSONWebKey{Key: TheKey.Public()}

// Return an ACME DNS identifier for the given hostname
func dnsi(hostname string) identifier.ACMEIdentifier {
	return identifier.NewDNS(hostname)
}

var ctx context.Context

func TestMain(m *testing.M) {
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Minute)
	ret := m.Run()
	cancel()
	os.Exit(ret)
}

var accountURIPrefixes = []string{"http://boulder.service.consul:4000/acme/reg/"}

func createValidationRequest(domain string, challengeType core.AcmeChallenge) *vapb.PerformValidationRequest {
	return &vapb.PerformValidationRequest{
		DnsName: domain,
		Challenge: &corepb.Challenge{
			Type:              string(challengeType),
			Status:            string(core.StatusPending),
			Token:             expectedToken,
			Validationrecords: nil,
		},
		Authz: &vapb.AuthzMeta{
			Id:    "",
			RegID: 1,
		},
		ExpectedKeyAuthorization: expectedKeyAuthorization,
	}
}

// setup returns an in-memory VA and a mock logger. The default resolver client
// is MockClient{}, but can be overridden.
//
// If remoteVAs is nil, this builds a VA that acts like a remote (and does not
// perform multi-perspective validation). Otherwise it acts like a primary.
func setup(srv *httptest.Server, userAgent string, remoteVAs []RemoteVA, mockDNSClientOverride bdns.Client) (*ValidationAuthorityImpl, *blog.Mock) {
	features.Reset()
	fc := clock.NewFake()

	logger := blog.NewMock()

	if userAgent == "" {
		userAgent = "user agent 1.0"
	}

	perspective := PrimaryPerspective
	if len(remoteVAs) == 0 {
		// We're being set up as a remote. Use a distinct perspective from other remotes
		// to better simulate what prod will be like.
		perspective = "example perspective " + core.RandomString(4)
	}

	va, err := NewValidationAuthorityImpl(
		&bdns.MockClient{Log: logger},
		remoteVAs,
		userAgent,
		"letsencrypt.org",
		metrics.NoopRegisterer,
		fc,
		logger,
		accountURIPrefixes,
		perspective,
		"",
	)
	if err != nil {
		panic(fmt.Sprintf("Failed to create validation authority: %v", err))
	}

	if mockDNSClientOverride != nil {
		va.dnsClient = mockDNSClientOverride
	}

	// Adjusting industry regulated ACME challenge port settings is fine during
	// testing
	if srv != nil {
		port := getPort(srv)
		va.httpPort = port
		va.tlsPort = port
	}

	return va, logger
}

func setupRemote(srv *httptest.Server, userAgent string, mockDNSClientOverride bdns.Client, perspective, rir string) RemoteClients {
	rva, _ := setup(srv, userAgent, nil, mockDNSClientOverride)
	rva.perspective = perspective
	rva.rir = rir

	return RemoteClients{VAClient: &inMemVA{rva}, CAAClient: &inMemVA{rva}}
}

// RIRs
const (
	arin    = "ARIN"
	ripe    = "RIPE"
	apnic   = "APNIC"
	lacnic  = "LACNIC"
	afrinic = "AFRINIC"
)

// remoteConf is used in conjunction with setupRemotes/withRemotes to configure
// a remote VA.
type remoteConf struct {
	// ua is optional, will default to "user agent 1.0". When set to "broken" or
	// "hijacked", the Address field of the resulting RemoteVA will be set to
	// match. This is a bit hacky, but it's the easiest way to satisfy some of
	// our existing TestMultiCAARechecking tests.
	ua string
	// rir is required.
	rir string
	// dns is optional.
	dns bdns.Client
	// impl is optional.
	impl RemoteClients
}

func setupRemotes(confs []remoteConf, srv *httptest.Server) []RemoteVA {
	remoteVAs := make([]RemoteVA, 0, len(confs))
	for i, c := range confs {
		if c.rir == "" {
			panic("rir is required")
		}
		// perspective MUST be unique for each remote VA, otherwise the VA will
		// fail to start.
		perspective := fmt.Sprintf("dc-%d-%s", i, c.rir)
		clients := setupRemote(srv, c.ua, c.dns, perspective, c.rir)
		if c.impl != (RemoteClients{}) {
			clients = c.impl
		}
		var address string
		if c.ua == "broken" {
			address = "broken"
		}
		if c.ua == "hijacked" {
			address = "hijacked"
		}
		remoteVAs = append(remoteVAs, RemoteVA{
			Address:       address,
			RemoteClients: clients,
			Perspective:   perspective,
			RIR:           c.rir,
		})
	}

	return remoteVAs
}

func setupWithRemotes(srv *httptest.Server, userAgent string, remotes []remoteConf, mockDNSClientOverride bdns.Client) (*ValidationAuthorityImpl, *blog.Mock) {
	remoteVAs := setupRemotes(remotes, srv)
	return setup(srv, userAgent, remoteVAs, mockDNSClientOverride)
}

type multiSrv struct {
	*httptest.Server

	mu         sync.Mutex
	allowedUAs map[string]bool
}

const (
	slowUA                = "slow remote"
	slowRemoteSleepMillis = 1000
)

func httpMultiSrv(t *testing.T, token string, allowedUAs map[string]bool) *multiSrv {
	t.Helper()
	m := http.NewServeMux()

	server := httptest.NewUnstartedServer(m)
	ms := &multiSrv{server, sync.Mutex{}, allowedUAs}

	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() == slowUA {
			time.Sleep(slowRemoteSleepMillis)
		}
		ms.mu.Lock()
		defer ms.mu.Unlock()
		if ms.allowedUAs[r.UserAgent()] {
			ch := core.Challenge{Token: token}
			keyAuthz, _ := ch.ExpectedKeyAuthorization(accountKey)
			fmt.Fprint(w, keyAuthz, "\n\r \t")
		} else {
			fmt.Fprint(w, "???")
		}
	})

	ms.Start()
	return ms
}

// cancelledVA is a mock that always returns context.Canceled for
// PerformValidation calls
type cancelledVA struct{}

func (v cancelledVA) PerformValidation(_ context.Context, _ *vapb.PerformValidationRequest, _ ...grpc.CallOption) (*vapb.ValidationResult, error) {
	return nil, context.Canceled
}

func (v cancelledVA) DoDCV(_ context.Context, _ *vapb.PerformValidationRequest, _ ...grpc.CallOption) (*vapb.ValidationResult, error) {
	return nil, context.Canceled
}

func (v cancelledVA) IsCAAValid(_ context.Context, _ *vapb.IsCAAValidRequest, _ ...grpc.CallOption) (*vapb.IsCAAValidResponse, error) {
	return nil, context.Canceled
}

func (v cancelledVA) DoCAA(_ context.Context, _ *vapb.IsCAAValidRequest, _ ...grpc.CallOption) (*vapb.IsCAAValidResponse, error) {
	return nil, context.Canceled
}

// brokenRemoteVA is a mock for the VAClient and CAAClient interfaces that always return
// errors.
type brokenRemoteVA struct{}

// errBrokenRemoteVA is the error returned by a brokenRemoteVA's
// PerformValidation and IsSafeDomain functions.
var errBrokenRemoteVA = errors.New("brokenRemoteVA is broken")

// PerformValidation returns errBrokenRemoteVA unconditionally
func (b brokenRemoteVA) PerformValidation(_ context.Context, _ *vapb.PerformValidationRequest, _ ...grpc.CallOption) (*vapb.ValidationResult, error) {
	return nil, errBrokenRemoteVA
}

// DoDCV returns errBrokenRemoteVA unconditionally
func (b brokenRemoteVA) DoDCV(_ context.Context, _ *vapb.PerformValidationRequest, _ ...grpc.CallOption) (*vapb.ValidationResult, error) {
	return nil, errBrokenRemoteVA
}

func (b brokenRemoteVA) IsCAAValid(_ context.Context, _ *vapb.IsCAAValidRequest, _ ...grpc.CallOption) (*vapb.IsCAAValidResponse, error) {
	return nil, errBrokenRemoteVA
}

func (b brokenRemoteVA) DoCAA(_ context.Context, _ *vapb.IsCAAValidRequest, _ ...grpc.CallOption) (*vapb.IsCAAValidResponse, error) {
	return nil, errBrokenRemoteVA
}

// inMemVA is a wrapper which fulfills the VAClient and CAAClient
// interfaces, but then forwards requests directly to its inner
// ValidationAuthorityImpl rather than over the network. This lets a local
// in-memory mock VA act like a remote VA.
type inMemVA struct {
	rva *ValidationAuthorityImpl
}

func (inmem *inMemVA) PerformValidation(ctx context.Context, req *vapb.PerformValidationRequest, _ ...grpc.CallOption) (*vapb.ValidationResult, error) {
	return inmem.rva.PerformValidation(ctx, req)
}

func (inmem *inMemVA) DoDCV(ctx context.Context, req *vapb.PerformValidationRequest, _ ...grpc.CallOption) (*vapb.ValidationResult, error) {
	return inmem.rva.DoDCV(ctx, req)
}

func (inmem *inMemVA) IsCAAValid(ctx context.Context, req *vapb.IsCAAValidRequest, _ ...grpc.CallOption) (*vapb.IsCAAValidResponse, error) {
	return inmem.rva.IsCAAValid(ctx, req)
}

func (inmem *inMemVA) DoCAA(ctx context.Context, req *vapb.IsCAAValidRequest, _ ...grpc.CallOption) (*vapb.IsCAAValidResponse, error) {
	return inmem.rva.DoCAA(ctx, req)
}

func TestNewValidationAuthorityImplWithDuplicateRemotes(t *testing.T) {
	var remoteVAs []RemoteVA
	for i := 0; i < 3; i++ {
		remoteVAs = append(remoteVAs, RemoteVA{
			RemoteClients: setupRemote(nil, "", nil, "dadaist", arin),
			Perspective:   "dadaist",
			RIR:           arin,
		})
	}

	_, err := NewValidationAuthorityImpl(
		&bdns.MockClient{Log: blog.NewMock()},
		remoteVAs,
		"user agent 1.0",
		"letsencrypt.org",
		metrics.NoopRegisterer,
		clock.NewFake(),
		blog.NewMock(),
		accountURIPrefixes,
		"example perspective",
		"",
	)
	test.AssertError(t, err, "NewValidationAuthorityImpl allowed duplicate remote perspectives")
	test.AssertContains(t, err.Error(), "duplicate remote VA perspective \"dadaist\"")
}

type validationFuncRunner func(context.Context, *ValidationAuthorityImpl, *vapb.PerformValidationRequest) (*vapb.ValidationResult, error)

var runPerformValidation = func(ctx context.Context, va *ValidationAuthorityImpl, req *vapb.PerformValidationRequest) (*vapb.ValidationResult, error) {
	return va.PerformValidation(ctx, req)
}

var runDoDCV = func(ctx context.Context, va *ValidationAuthorityImpl, req *vapb.PerformValidationRequest) (*vapb.ValidationResult, error) {
	return va.DoDCV(ctx, req)
}

func TestPerformValidationWithMismatchedRemoteVAPerspectives(t *testing.T) {
	t.Parallel()

	mismatched1 := RemoteVA{
		RemoteClients: setupRemote(nil, "", nil, "dadaist", arin),
		Perspective:   "baroque",
		RIR:           arin,
	}
	mismatched2 := RemoteVA{
		RemoteClients: setupRemote(nil, "", nil, "impressionist", ripe),
		Perspective:   "minimalist",
		RIR:           ripe,
	}
	remoteVAs := setupRemotes([]remoteConf{{rir: ripe}}, nil)
	remoteVAs = append(remoteVAs, mismatched1, mismatched2)

	testCases := []struct {
		validationFuncName string
		validationFunc     validationFuncRunner
	}{
		{
			validationFuncName: "PerformValidation",
			validationFunc:     runPerformValidation,
		},
		{
			validationFuncName: "DoDCV",
			validationFunc:     runDoDCV,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.validationFuncName, func(t *testing.T) {
			t.Parallel()

			va, mockLog := setup(nil, "", remoteVAs, nil)
			req := createValidationRequest("good-dns01.com", core.ChallengeTypeDNS01)
			res, _ := tc.validationFunc(context.Background(), va, req)
			test.AssertNotNil(t, res.GetProblem(), "validation succeeded with mismatched remote VA perspectives")
			test.AssertEquals(t, len(mockLog.GetAllMatching("Expected perspective")), 2)
		})
	}
}

func TestPerformValidationWithMismatchedRemoteVARIRs(t *testing.T) {
	t.Parallel()

	mismatched1 := RemoteVA{
		RemoteClients: setupRemote(nil, "", nil, "dadaist", arin),
		Perspective:   "dadaist",
		RIR:           ripe,
	}
	mismatched2 := RemoteVA{
		RemoteClients: setupRemote(nil, "", nil, "impressionist", ripe),
		Perspective:   "impressionist",
		RIR:           arin,
	}
	remoteVAs := setupRemotes([]remoteConf{{rir: ripe}}, nil)
	remoteVAs = append(remoteVAs, mismatched1, mismatched2)

	testCases := []struct {
		validationFuncName string
		validationFunc     validationFuncRunner
	}{
		{
			validationFuncName: "PerformValidation",
			validationFunc:     runPerformValidation,
		},
		{
			validationFuncName: "DoDCV",
			validationFunc:     runDoDCV,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.validationFuncName, func(t *testing.T) {
			t.Parallel()

			va, mockLog := setup(nil, "", remoteVAs, nil)
			req := createValidationRequest("good-dns01.com", core.ChallengeTypeDNS01)
			res, _ := tc.validationFunc(context.Background(), va, req)
			test.AssertNotNil(t, res.GetProblem(), "validation succeeded with mismatched remote VA perspectives")
			test.AssertEquals(t, len(mockLog.GetAllMatching("Expected perspective")), 2)
		})
	}
}

func TestValidateMalformedChallenge(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)

	_, err := va.validateChallenge(ctx, dnsi("example.com"), "fake-type-01", expectedToken, expectedKeyAuthorization)

	prob := detailedError(err)
	test.AssertEquals(t, prob.Type, probs.MalformedProblem)
}

func TestPerformValidationInvalid(t *testing.T) {
	t.Parallel()
	va, _ := setup(nil, "", nil, nil)

	testCases := []struct {
		validationFuncName string
		validationFunc     validationFuncRunner
	}{
		{
			validationFuncName: "PerformValidation",
			validationFunc:     runPerformValidation,
		},
		{
			validationFuncName: "DoDCV",
			validationFunc:     runDoDCV,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.validationFuncName, func(t *testing.T) {
			t.Parallel()

			req := createValidationRequest("foo.com", core.ChallengeTypeDNS01)
			res, _ := tc.validationFunc(context.Background(), va, req)
			test.Assert(t, res.Problem != nil, "validation succeeded")
			if tc.validationFuncName == "PerformValidation" {
				test.AssertMetricWithLabelsEquals(t, va.metrics.validationLatency, prometheus.Labels{
					"operation":      opDCVAndCAA,
					"perspective":    va.perspective,
					"challenge_type": string(core.ChallengeTypeDNS01),
					"problem_type":   string(probs.UnauthorizedProblem),
					"result":         fail,
				}, 1)
			} else {
				test.AssertMetricWithLabelsEquals(t, va.metrics.validationLatency, prometheus.Labels{
					"operation":      opDCV,
					"perspective":    va.perspective,
					"challenge_type": string(core.ChallengeTypeDNS01),
					"problem_type":   string(probs.UnauthorizedProblem),
					"result":         fail,
				}, 1)
			}
		})
	}
}

func TestInternalErrorLogged(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		validationFuncName string
		validationFunc     validationFuncRunner
	}{
		{
			validationFuncName: "PerformValidation",
			validationFunc:     runPerformValidation,
		},
		{
			validationFuncName: "DoDCV",
			validationFunc:     runDoDCV,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.validationFuncName, func(t *testing.T) {
			t.Parallel()

			va, mockLog := setup(nil, "", nil, nil)

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
			defer cancel()
			req := createValidationRequest("nonexistent.com", core.ChallengeTypeHTTP01)
			_, err := tc.validationFunc(ctx, va, req)
			test.AssertNotError(t, err, "failed validation should not be an error")
			matchingLogs := mockLog.GetAllMatching(
				`Validation result JSON=.*"InternalError":"127.0.0.1: Get.*nonexistent.com/\.well-known.*: context deadline exceeded`)
			test.AssertEquals(t, len(matchingLogs), 1)
		})
	}
}

func TestPerformValidationValid(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		validationFuncName string
		validationFunc     validationFuncRunner
	}{
		{
			validationFuncName: "PerformValidation",
			validationFunc:     runPerformValidation,
		},
		{
			validationFuncName: "DoDCV",
			validationFunc:     runDoDCV,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.validationFuncName, func(t *testing.T) {
			t.Parallel()

			va, mockLog := setup(nil, "", nil, nil)

			// create a challenge with well known token
			req := createValidationRequest("good-dns01.com", core.ChallengeTypeDNS01)
			res, _ := tc.validationFunc(context.Background(), va, req)
			test.Assert(t, res.Problem == nil, fmt.Sprintf("validation failed: %#v", res.Problem))
			if tc.validationFuncName == "PerformValidation" {
				test.AssertMetricWithLabelsEquals(t, va.metrics.validationLatency, prometheus.Labels{
					"operation":      opDCVAndCAA,
					"perspective":    va.perspective,
					"challenge_type": string(core.ChallengeTypeDNS01),
					"problem_type":   "",
					"result":         pass,
				}, 1)
			} else {
				test.AssertMetricWithLabelsEquals(t, va.metrics.validationLatency, prometheus.Labels{
					"operation":      opDCV,
					"perspective":    va.perspective,
					"challenge_type": string(core.ChallengeTypeDNS01),
					"problem_type":   "",
					"result":         pass,
				}, 1)
			}
			resultLog := mockLog.GetAllMatching(`Validation result`)
			if len(resultLog) != 1 {
				t.Fatalf("Wrong number of matching lines for 'Validation result'")
			}
			if !strings.Contains(resultLog[0], `"Identifier":"good-dns01.com"`) {
				t.Error("PerformValidation didn't log validation identifier.")
			}
		})
	}
}

// TestPerformValidationWildcard tests that the VA properly strips the `*.`
// prefix from a wildcard name provided to the PerformValidation function.
func TestPerformValidationWildcard(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		validationFuncName string
		validationFunc     validationFuncRunner
	}{
		{
			validationFuncName: "PerformValidation",
			validationFunc:     runPerformValidation,
		},
		{
			validationFuncName: "DoDCV",
			validationFunc:     runDoDCV,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.validationFuncName, func(t *testing.T) {
			t.Parallel()

			va, mockLog := setup(nil, "", nil, nil)

			// create a challenge with well known token
			req := createValidationRequest("*.good-dns01.com", core.ChallengeTypeDNS01)
			// perform a validation for a wildcard name
			res, _ := tc.validationFunc(context.Background(), va, req)
			test.Assert(t, res.Problem == nil, fmt.Sprintf("validation failed: %#v", res.Problem))
			if tc.validationFuncName == "PerformValidation" {
				test.AssertMetricWithLabelsEquals(t, va.metrics.validationLatency, prometheus.Labels{
					"operation":      opDCVAndCAA,
					"perspective":    va.perspective,
					"challenge_type": string(core.ChallengeTypeDNS01),
					"problem_type":   "",
					"result":         pass,
				}, 1)
			} else {
				test.AssertMetricWithLabelsEquals(t, va.metrics.validationLatency, prometheus.Labels{
					"operation":      opDCV,
					"perspective":    va.perspective,
					"challenge_type": string(core.ChallengeTypeDNS01),
					"problem_type":   "",
					"result":         pass,
				}, 1)
			}
			resultLog := mockLog.GetAllMatching(`Validation result`)
			if len(resultLog) != 1 {
				t.Fatalf("Wrong number of matching lines for 'Validation result'")
			}

			// We expect that the top level Identifier reflect the wildcard name
			if !strings.Contains(resultLog[0], `"Identifier":"*.good-dns01.com"`) {
				t.Errorf("PerformValidation didn't log correct validation identifier.")
			}
			// We expect that the ValidationRecord contain the correct non-wildcard
			// hostname that was validated
			if !strings.Contains(resultLog[0], `"hostname":"good-dns01.com"`) {
				t.Errorf("PerformValidation didn't log correct validation record hostname.")
			}
		})
	}
}

func TestDCVAndCAASequencing(t *testing.T) {
	va, mockLog := setup(nil, "", nil, nil)

	// When validation succeeds, CAA should be checked.
	mockLog.Clear()
	req := createValidationRequest("good-dns01.com", core.ChallengeTypeDNS01)
	res, err := va.PerformValidation(context.Background(), req)
	test.AssertNotError(t, err, "performing validation")
	test.Assert(t, res.Problem == nil, fmt.Sprintf("validation failed: %#v", res.Problem))
	caaLog := mockLog.GetAllMatching(`Checked CAA records for`)
	test.AssertEquals(t, len(caaLog), 1)

	// When validation fails, CAA should be skipped.
	mockLog.Clear()
	req = createValidationRequest("bad-dns01.com", core.ChallengeTypeDNS01)
	res, err = va.PerformValidation(context.Background(), req)
	test.AssertNotError(t, err, "performing validation")
	test.Assert(t, res.Problem != nil, "validation succeeded")
	caaLog = mockLog.GetAllMatching(`Checked CAA records for`)
	test.AssertEquals(t, len(caaLog), 0)
}

func TestPerformRemoteOperation(t *testing.T) {
	va, _ := setupWithRemotes(nil, "", []remoteConf{
		{ua: pass, rir: arin},
		{ua: pass, rir: ripe},
		{ua: pass, rir: apnic},
	}, nil)

	testCases := []struct {
		name           string
		req            proto.Message
		expectedType   string
		expectedDetail string
		op             func(ctx context.Context, rva RemoteVA, req proto.Message) (remoteResult, error)
	}{
		{
			name:           "ValidationResult",
			req:            &vapb.PerformValidationRequest{},
			expectedType:   string(probs.BadNonceProblem),
			expectedDetail: "quite surprising",
			op: func(ctx context.Context, rva RemoteVA, req proto.Message) (remoteResult, error) {
				prob := &corepb.ProblemDetails{
					ProblemType: string(probs.BadNonceProblem),
					Detail:      "quite surprising",
				}
				return &vapb.ValidationResult{Problem: prob, Perspective: rva.Perspective, Rir: rva.RIR}, nil
			},
		},
		{
			name:           "IsCAAValidResponse",
			req:            &vapb.IsCAAValidRequest{},
			expectedType:   string(probs.PausedProblem),
			expectedDetail: "quite surprising, indeed",
			op: func(ctx context.Context, rva RemoteVA, req proto.Message) (remoteResult, error) {
				prob := &corepb.ProblemDetails{
					ProblemType: string(probs.PausedProblem),
					Detail:      "quite surprising, indeed",
				}
				return &vapb.IsCAAValidResponse{Problem: prob, Perspective: rva.Perspective, Rir: rva.RIR}, nil
			},
		},
		{
			name:           "IsCAAValidRequestWithValidationResult",
			req:            &vapb.IsCAAValidRequest{},
			expectedType:   string(probs.BadPublicKeyProblem),
			expectedDetail: "a shocking result",
			op: func(ctx context.Context, rva RemoteVA, req proto.Message) (remoteResult, error) {
				prob := &corepb.ProblemDetails{
					ProblemType: string(probs.BadPublicKeyProblem),
					Detail:      "a shocking result",
				}
				return &vapb.ValidationResult{Problem: prob, Perspective: rva.Perspective, Rir: rva.RIR}, nil
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			prob := va.performRemoteOperation(context.Background(), tc.op, tc.req)
			test.AssertEquals(t, string(prob.Type), tc.expectedType)
			test.AssertContains(t, prob.Detail, tc.expectedDetail)
		})
	}
}

func TestMultiVA(t *testing.T) {
	t.Parallel()

	// Create a new challenge to use for the httpSrv
	req := createValidationRequest("localhost", core.ChallengeTypeHTTP01)

	brokenVA := RemoteClients{
		VAClient:  brokenRemoteVA{},
		CAAClient: brokenRemoteVA{},
	}
	cancelledVA := RemoteClients{
		VAClient:  cancelledVA{},
		CAAClient: cancelledVA{},
	}

	type testFunc struct {
		name string
		impl validationFuncRunner
	}

	testFuncs := []testFunc{
		{
			name: "PerformValidation",
			impl: runPerformValidation,
		},
		{
			name: "DoDCV",
			impl: runDoDCV,
		},
	}

	testCases := []struct {
		Name                string
		Remotes             []remoteConf
		PrimaryUA           string
		ExpectedProbType    string
		ExpectedLogContains string
	}{
		{
			// With local and all remote VAs working there should be no problem.
			Name: "Local and remote VAs OK",
			Remotes: []remoteConf{
				{ua: pass, rir: arin},
				{ua: pass, rir: ripe},
				{ua: pass, rir: apnic},
			},
			PrimaryUA: pass,
		},
		{
			// If the local VA fails everything should fail
			Name: "Local VA bad, remote VAs OK",
			Remotes: []remoteConf{
				{ua: pass, rir: arin},
				{ua: pass, rir: ripe},
				{ua: pass, rir: apnic},
			},
			PrimaryUA:        fail,
			ExpectedProbType: string(probs.UnauthorizedProblem),
		},
		{
			// If one out of three remote VAs fails with an internal err it should succeed
			Name: "Local VA ok, 1/3 remote VA internal err",
			Remotes: []remoteConf{
				{ua: pass, rir: arin},
				{ua: pass, rir: ripe},
				{ua: pass, rir: apnic, impl: brokenVA},
			},
			PrimaryUA: pass,
		},
		{
			// If two out of three remote VAs fail with an internal err it should fail
			Name: "Local VA ok, 2/3 remote VAs internal err",
			Remotes: []remoteConf{
				{ua: pass, rir: arin},
				{ua: pass, rir: ripe, impl: brokenVA},
				{ua: pass, rir: apnic, impl: brokenVA},
			},
			PrimaryUA:        pass,
			ExpectedProbType: string(probs.ServerInternalProblem),
			// The real failure cause should be logged
			ExpectedLogContains: errBrokenRemoteVA.Error(),
		},
		{
			// If one out of five remote VAs fail with an internal err it should succeed
			Name: "Local VA ok, 1/5 remote VAs internal err",
			Remotes: []remoteConf{
				{ua: pass, rir: arin},
				{ua: pass, rir: ripe},
				{ua: pass, rir: apnic},
				{ua: pass, rir: lacnic},
				{ua: pass, rir: afrinic, impl: brokenVA},
			},
			PrimaryUA: pass,
		},
		{
			// If two out of five remote VAs fail with an internal err it should fail
			Name: "Local VA ok, 2/5 remote VAs internal err",
			Remotes: []remoteConf{
				{ua: pass, rir: arin},
				{ua: pass, rir: ripe},
				{ua: pass, rir: apnic},
				{ua: pass, rir: arin, impl: brokenVA},
				{ua: pass, rir: ripe, impl: brokenVA},
			},
			PrimaryUA:        pass,
			ExpectedProbType: string(probs.ServerInternalProblem),
			// The real failure cause should be logged
			ExpectedLogContains: errBrokenRemoteVA.Error(),
		},
		{
			// If two out of six remote VAs fail with an internal err it should succeed
			Name: "Local VA ok, 2/6 remote VAs internal err",
			Remotes: []remoteConf{
				{ua: pass, rir: arin},
				{ua: pass, rir: ripe},
				{ua: pass, rir: apnic},
				{ua: pass, rir: lacnic},
				{ua: pass, rir: afrinic, impl: brokenVA},
				{ua: pass, rir: arin, impl: brokenVA},
			},
			PrimaryUA: pass,
		},
		{
			// If three out of six remote VAs fail with an internal err it should fail
			Name: "Local VA ok, 4/6 remote VAs internal err",
			Remotes: []remoteConf{
				{ua: pass, rir: arin},
				{ua: pass, rir: ripe},
				{ua: pass, rir: apnic},
				{ua: pass, rir: lacnic, impl: brokenVA},
				{ua: pass, rir: afrinic, impl: brokenVA},
				{ua: pass, rir: arin, impl: brokenVA},
			},
			PrimaryUA:        pass,
			ExpectedProbType: string(probs.ServerInternalProblem),
			// The real failure cause should be logged
			ExpectedLogContains: errBrokenRemoteVA.Error(),
		},
		{
			// With only one working remote VA there should be a validation failure
			Name: "Local VA and one remote VA OK",
			Remotes: []remoteConf{
				{ua: pass, rir: arin},
				{ua: fail, rir: ripe},
				{ua: fail, rir: apnic},
			},
			PrimaryUA:           pass,
			ExpectedProbType:    string(probs.UnauthorizedProblem),
			ExpectedLogContains: "During secondary validation: The key authorization file from the server",
		},
		{
			// If one remote VA cancels, it should succeed
			Name: "Local VA and one remote VA OK, one cancelled VA",
			Remotes: []remoteConf{
				{ua: pass, rir: arin},
				{ua: pass, rir: ripe, impl: cancelledVA},
				{ua: pass, rir: apnic},
			},
			PrimaryUA: pass,
		},
		{
			// If all remote VAs cancel, it should fail
			Name: "Local VA OK, three cancelled remote VAs",
			Remotes: []remoteConf{
				{ua: pass, rir: arin, impl: cancelledVA},
				{ua: pass, rir: ripe, impl: cancelledVA},
				{ua: pass, rir: apnic, impl: cancelledVA},
			},
			PrimaryUA:           pass,
			ExpectedProbType:    string(probs.ServerInternalProblem),
			ExpectedLogContains: "During secondary validation: Secondary validation RPC canceled",
		},
		{
			// With the local and remote VAs seeing diff problems, we expect a problem.
			Name: "Local and remote VA differential, full results, enforce multi VA",
			Remotes: []remoteConf{
				{ua: fail, rir: arin},
				{ua: fail, rir: ripe},
				{ua: fail, rir: apnic},
			},
			PrimaryUA:           pass,
			ExpectedProbType:    string(probs.UnauthorizedProblem),
			ExpectedLogContains: "During secondary validation: The key authorization file from the server",
		},
	}

	for _, tc := range testCases {
		for _, testFunc := range testFuncs {
			t.Run(tc.Name+"_"+testFunc.name, func(t *testing.T) {
				t.Parallel()

				// Configure one test server per test case so that all tests can run in parallel.
				ms := httpMultiSrv(t, expectedToken, map[string]bool{pass: true, fail: false})
				defer ms.Close()

				// Configure a primary VA with testcase remote VAs.
				localVA, mockLog := setupWithRemotes(ms.Server, tc.PrimaryUA, tc.Remotes, nil)

				// Perform all validations
				res, _ := testFunc.impl(ctx, localVA, req)
				if res.Problem == nil && tc.ExpectedProbType != "" {
					t.Errorf("expected prob %v, got nil", tc.ExpectedProbType)
				} else if res.Problem != nil && tc.ExpectedProbType == "" {
					t.Errorf("expected no prob, got %v", res.Problem)
				} else if res.Problem != nil && tc.ExpectedProbType != "" {
					// That result should match expected.
					test.AssertEquals(t, res.Problem.ProblemType, tc.ExpectedProbType)
				}

				if tc.ExpectedLogContains != "" {
					lines := mockLog.GetAllMatching(tc.ExpectedLogContains)
					if len(lines) == 0 {
						t.Fatalf("Got log %v; expected %q", mockLog.GetAll(), tc.ExpectedLogContains)
					}
				}
			})
		}
	}
}

func TestMultiVAEarlyReturn(t *testing.T) {
	t.Parallel()

	type testFunc struct {
		name string
		impl validationFuncRunner
	}

	testFuncs := []testFunc{
		{
			name: "PerformValidation",
			impl: runPerformValidation,
		},
		{
			name: "DoDCV",
			impl: runDoDCV,
		},
	}

	testCases := []struct {
		remoteConfs []remoteConf
	}{
		{
			remoteConfs: []remoteConf{
				{ua: slowUA, rir: arin},
				{ua: pass, rir: ripe},
				{ua: fail, rir: apnic},
			},
		},
		{
			remoteConfs: []remoteConf{
				{ua: slowUA, rir: arin},
				{ua: slowUA, rir: ripe},
				{ua: pass, rir: apnic},
				{ua: pass, rir: arin},
				{ua: fail, rir: ripe},
			},
		},
		{
			remoteConfs: []remoteConf{
				{ua: slowUA, rir: arin},
				{ua: slowUA, rir: ripe},
				{ua: pass, rir: apnic},
				{ua: pass, rir: arin},
				{ua: fail, rir: ripe},
				{ua: fail, rir: apnic},
			},
		},
	}

	for i, tc := range testCases {
		for _, testFunc := range testFuncs {
			t.Run(fmt.Sprintf("case %d"+"_"+testFunc.name, i), func(t *testing.T) {
				t.Parallel()

				// Configure one test server per test case so that all tests can run in parallel.
				ms := httpMultiSrv(t, expectedToken, map[string]bool{pass: true, fail: false})
				defer ms.Close()

				localVA, _ := setupWithRemotes(ms.Server, pass, tc.remoteConfs, nil)

				// Perform all validations
				start := time.Now()
				req := createValidationRequest("localhost", core.ChallengeTypeHTTP01)
				res, _ := testFunc.impl(ctx, localVA, req)

				// It should always fail
				if res.Problem == nil {
					t.Error("expected prob from PerformValidation, got nil")
				}

				elapsed := time.Since(start).Round(time.Millisecond).Milliseconds()

				// The slow UA should sleep for `slowRemoteSleepMillis`. But the first remote
				// VA should fail quickly and the early-return code should cause the overall
				// overall validation to return a prob quickly (i.e. in less than half of
				// `slowRemoteSleepMillis`).
				if elapsed > slowRemoteSleepMillis/2 {
					t.Errorf(
						"Expected an early return from PerformValidation in < %d ms, took %d ms",
						slowRemoteSleepMillis/2, elapsed)
				}
			})
		}
	}
}

func TestMultiVAPolicy(t *testing.T) {
	t.Parallel()

	remoteConfs := []remoteConf{
		{ua: fail, rir: arin},
		{ua: fail, rir: ripe},
		{ua: fail, rir: apnic},
	}

	testCases := []struct {
		validationFuncName string
		validationFunc     validationFuncRunner
	}{
		{
			validationFuncName: "PerformValidation",
			validationFunc:     runPerformValidation,
		},
		{
			validationFuncName: "DoDCV",
			validationFunc:     runDoDCV,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.validationFuncName, func(t *testing.T) {
			t.Parallel()

			ms := httpMultiSrv(t, expectedToken, map[string]bool{pass: true, fail: false})
			defer ms.Close()

			// Create a local test VA with the remote VAs
			localVA, _ := setupWithRemotes(ms.Server, pass, remoteConfs, nil)

			// Perform validation for a domain not in the disabledDomains list
			req := createValidationRequest("letsencrypt.org", core.ChallengeTypeHTTP01)
			res, _ := tc.validationFunc(ctx, localVA, req)
			// It should fail
			if res.Problem == nil {
				t.Error("expected prob from PerformValidation, got nil")
			}
		})
	}
}

func TestMultiVALogging(t *testing.T) {
	t.Parallel()

	remoteConfs := []remoteConf{
		{ua: pass, rir: arin},
		{ua: pass, rir: ripe},
		{ua: pass, rir: apnic},
	}

	testCases := []struct {
		validationFuncName string
		validationFunc     validationFuncRunner
	}{
		{
			validationFuncName: "PerformValidation",
			validationFunc:     runPerformValidation,
		},
		{
			validationFuncName: "DoDCV",
			validationFunc:     runDoDCV,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.validationFuncName, func(t *testing.T) {
			t.Parallel()

			ms := httpMultiSrv(t, expectedToken, map[string]bool{pass: true, fail: false})
			defer ms.Close()

			va, _ := setupWithRemotes(ms.Server, pass, remoteConfs, nil)
			req := createValidationRequest("letsencrypt.org", core.ChallengeTypeHTTP01)
			res, err := tc.validationFunc(ctx, va, req)
			test.Assert(t, res.Problem == nil, fmt.Sprintf("validation failed with: %#v", res.Problem))
			test.AssertNotError(t, err, "performing validation")
		})
	}
}

func TestDetailedError(t *testing.T) {
	cases := []struct {
		err      error
		ip       net.IP
		expected string
	}{
		{
			err: ipError{
				ip: net.ParseIP("192.168.1.1"),
				err: &net.OpError{
					Op:  "dial",
					Net: "tcp",
					Err: &os.SyscallError{
						Syscall: "getsockopt",
						Err:     syscall.ECONNREFUSED,
					},
				},
			},
			expected: "192.168.1.1: Connection refused",
		},
		{
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: &os.SyscallError{
					Syscall: "getsockopt",
					Err:     syscall.ECONNREFUSED,
				},
			},
			expected: "Connection refused",
		},
		{
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: &os.SyscallError{
					Syscall: "getsockopt",
					Err:     syscall.ECONNRESET,
				},
			},
			ip:       nil,
			expected: "Connection reset by peer",
		},
	}
	for _, tc := range cases {
		actual := detailedError(tc.err).Detail
		if actual != tc.expected {
			t.Errorf("Wrong detail for %v. Got %q, expected %q", tc.err, actual, tc.expected)
		}
	}
}

func TestLogRemoteDifferentials(t *testing.T) {
	t.Parallel()

	remoteConfs := []remoteConf{
		{ua: pass, rir: arin},
		{ua: pass, rir: ripe},
		{ua: pass, rir: apnic},
	}

	testCases := []struct {
		name        string
		req         *vapb.IsCAAValidRequest
		passed      int
		failed      int
		expectedLog string
	}{
		{
			name:        "all results equal (nil)",
			passed:      0,
			failed:      3,
			expectedLog: `INFO: remoteVADifferentials JSON={"Domain":"example.com","AccountID":1999,"ChallengeType":"blorpus-01","RemoteSuccesses":0,"RemoteFailures":3}`,
		},
		{
			name:        "all results equal (not nil)",
			passed:      0,
			failed:      3,
			expectedLog: `INFO: remoteVADifferentials JSON={"Domain":"example.com","AccountID":1999,"ChallengeType":"blorpus-01","RemoteSuccesses":0,"RemoteFailures":3}`,
		},
		{
			name:        "differing results, some non-nil",
			passed:      2,
			failed:      1,
			expectedLog: `INFO: remoteVADifferentials JSON={"Domain":"example.com","AccountID":1999,"ChallengeType":"blorpus-01","RemoteSuccesses":2,"RemoteFailures":1}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Configure one test server per test case so that all tests can run in parallel.
			ms := httpMultiSrv(t, expectedToken, map[string]bool{pass: true, fail: false})
			defer ms.Close()

			localVA, mockLog := setupWithRemotes(ms.Server, pass, remoteConfs, nil)

			localVA.logRemoteResults(&vapb.IsCAAValidRequest{
				Domain:           "example.com",
				AccountURIID:     1999,
				ValidationMethod: "blorpus-01",
			}, tc.passed, tc.failed)

			lines := mockLog.GetAllMatching("remoteVADifferentials JSON=.*")
			if tc.expectedLog != "" {
				test.AssertEquals(t, len(lines), 1)
				test.AssertEquals(t, lines[0], tc.expectedLog)
			} else {
				test.AssertEquals(t, len(lines), 0)
			}
		})
	}
}
