package va

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/jmhodges/clock"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
	"gopkg.in/square/go-jose.v1"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/metrics/mock_metrics"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"
)

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

var accountKey = &jose.JsonWebKey{Key: TheKey.Public()}

var ident = core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "localhost"}

var ctx = context.Background()

// All paths that get assigned to tokens MUST be valid tokens
const expectedToken = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
const expectedKeyAuthorization = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0.9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI"
const pathWrongToken = "i6lNAC4lOOLYCl-A08VJt9z_tKYvVk63Dumo8icsBjQ"
const path404 = "404"
const path500 = "500"
const pathFound = "GBq8SwWq3JsbREFdCamk5IX3KLsxW5ULeGs98Ajl_UM"
const pathMoved = "5J4FIMrWNfmvHZo-QpKZngmuhqZGwRm21-oEgUDstJM"
const pathRedirectPort = "port-redirect"
const pathWait = "wait"
const pathWaitLong = "wait-long"
const pathReLookup = "7e-P57coLM7D3woNTp_xbJrtlkDYy6PWf3mSSbLwCr4"
const pathReLookupInvalid = "re-lookup-invalid"
const pathRedirectToFailingURL = "re-to-failing-url"
const pathLooper = "looper"
const pathValid = "valid"
const rejectUserAgent = "rejectMe"

func httpSrv(t *testing.T, token string) *httptest.Server {
	m := http.NewServeMux()

	server := httptest.NewUnstartedServer(m)

	defaultToken := token
	currentToken := defaultToken

	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, path404) {
			t.Logf("HTTPSRV: Got a 404 req\n")
			http.NotFound(w, r)
		} else if strings.HasSuffix(r.URL.Path, path500) {
			t.Logf("HTTPSRV: Got a 500 req\n")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		} else if strings.HasSuffix(r.URL.Path, pathMoved) {
			t.Logf("HTTPSRV: Got a 301 redirect req\n")
			if currentToken == defaultToken {
				currentToken = pathMoved
			}
			http.Redirect(w, r, pathValid, 301)
		} else if strings.HasSuffix(r.URL.Path, pathFound) {
			t.Logf("HTTPSRV: Got a 302 redirect req\n")
			if currentToken == defaultToken {
				currentToken = pathFound
			}
			http.Redirect(w, r, pathMoved, 302)
		} else if strings.HasSuffix(r.URL.Path, pathWait) {
			t.Logf("HTTPSRV: Got a wait req\n")
			time.Sleep(time.Second * 3)
		} else if strings.HasSuffix(r.URL.Path, pathWaitLong) {
			t.Logf("HTTPSRV: Got a wait-long req\n")
			time.Sleep(time.Second * 10)
		} else if strings.HasSuffix(r.URL.Path, pathReLookup) {
			t.Logf("HTTPSRV: Got a redirect req to a valid hostname\n")
			if currentToken == defaultToken {
				currentToken = pathReLookup
			}
			port := getPort(server)
			http.Redirect(w, r, fmt.Sprintf("http://other.valid:%d/path", port), 302)
		} else if strings.HasSuffix(r.URL.Path, pathReLookupInvalid) {
			t.Logf("HTTPSRV: Got a redirect req to an invalid hostname\n")
			http.Redirect(w, r, "http://invalid.invalid/path", 302)
		} else if strings.HasSuffix(r.URL.Path, pathRedirectToFailingURL) {
			t.Logf("HTTPSRV: Redirecting to a URL that will fail\n")
			http.Redirect(w, r, fmt.Sprintf("http://other.valid/%s", path500), 301)
		} else if strings.HasSuffix(r.URL.Path, pathLooper) {
			t.Logf("HTTPSRV: Got a loop req\n")
			http.Redirect(w, r, r.URL.String(), 301)
		} else if strings.HasSuffix(r.URL.Path, pathRedirectPort) {
			t.Logf("HTTPSRV: Got a port redirect req\n")
			http.Redirect(w, r, "http://other.valid:8080/path", 302)
		} else if r.Header.Get("User-Agent") == rejectUserAgent {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("found trap User-Agent"))
		} else {
			t.Logf("HTTPSRV: Got a valid req\n")
			t.Logf("HTTPSRV: Path = %s\n", r.URL.Path)

			ch := core.Challenge{Token: currentToken}
			keyAuthz, _ := ch.ExpectedKeyAuthorization(accountKey)
			t.Logf("HTTPSRV: Key Authz = '%s%s'\n", keyAuthz, "\\n\\r \\t")

			fmt.Fprint(w, keyAuthz, "\n\r \t")
			currentToken = defaultToken
		}
	})

	server.Start()
	return server
}

func tlssni01Srv(t *testing.T, chall core.Challenge) *httptest.Server {
	h := sha256.Sum256([]byte(chall.ProvidedKeyAuthorization))
	Z := hex.EncodeToString(h[:])
	ZName := fmt.Sprintf("%s.%s.acme.invalid", Z[:32], Z[32:])

	return tlssniSrvWithNames(t, chall, ZName)
}

func tlssni02Srv(t *testing.T, chall core.Challenge) *httptest.Server {
	ha := sha256.Sum256([]byte(chall.Token))
	za := hex.EncodeToString(ha[:])
	sanAName := fmt.Sprintf("%s.%s.token.acme.invalid", za[:32], za[32:])

	hb := sha256.Sum256([]byte(chall.ProvidedKeyAuthorization))
	zb := hex.EncodeToString(hb[:])
	sanBName := fmt.Sprintf("%s.%s.ka.acme.invalid", zb[:32], zb[32:])

	return tlssniSrvWithNames(t, chall, sanAName, sanBName)
}

func tlssniSrvWithNames(t *testing.T, chall core.Challenge, names ...string) *httptest.Server {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1337),
		Subject: pkix.Name{
			Organization: []string{"tests"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 1),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		DNSNames: names,
	}

	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &TheKey.PublicKey, &TheKey)
	cert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  &TheKey,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		ClientAuth:   tls.NoClientCert,
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if clientHello.ServerName != names[0] {
				time.Sleep(time.Second * 10)
				return nil, nil
			}
			return cert, nil
		},
		NextProtos: []string{"http/1.1"},
	}

	hs := httptest.NewUnstartedServer(http.DefaultServeMux)
	hs.TLS = tlsConfig
	hs.StartTLS()
	return hs
}

func TestHTTPBadPort(t *testing.T) {
	chall := core.HTTPChallenge01()
	setChallengeToken(&chall, expectedToken)

	hs := httpSrv(t, chall.Token)
	defer hs.Close()

	va, _ := setup(hs)

	// Pick a random port between 40000 and 65000 - with great certainty we won't
	// have an HTTP server listening on this port and the test will fail as
	// intended
	badPort := 40000 + mrand.Intn(25000)
	va.httpPort = badPort

	_, prob := va.validateHTTP01(ctx, ident, chall)
	if prob == nil {
		t.Fatalf("Server's down; expected refusal. Where did we connect?")
	}
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)
}

func TestHTTP(t *testing.T) {
	chall := core.HTTPChallenge01()
	setChallengeToken(&chall, expectedToken)

	// NOTE: We do not attempt to shut down the server. The problem is that the
	// "wait-long" handler sleeps for ten seconds, but this test finishes in less
	// than that. So if we try to call hs.Close() at the end of the test, we'll be
	// closing the test server while a request is still pending. Unfortunately,
	// there appears to be an issue in httptest that trips Go's race detector when
	// that happens, failing the test. So instead, we live with leaving the server
	// around till the process exits.
	// TODO(#1989): close hs
	hs := httpSrv(t, chall.Token)

	va, log := setup(hs)

	log.Clear()
	t.Logf("Trying to validate: %+v\n", chall)
	_, prob := va.validateHTTP01(ctx, ident, chall)
	if prob != nil {
		t.Errorf("Unexpected failure in HTTP validation: %s", prob)
	}
	test.AssertEquals(t, len(log.GetAllMatching(`\[AUDIT\] `)), 1)

	log.Clear()
	setChallengeToken(&chall, path404)
	_, prob = va.validateHTTP01(ctx, ident, chall)
	if prob == nil {
		t.Fatalf("Should have found a 404 for the challenge.")
	}
	test.AssertEquals(t, prob.Type, probs.UnauthorizedProblem)
	test.AssertEquals(t, len(log.GetAllMatching(`\[AUDIT\] `)), 1)

	log.Clear()
	setChallengeToken(&chall, pathWrongToken)
	// The "wrong token" will actually be the expectedToken.  It's wrong
	// because it doesn't match pathWrongToken.
	_, prob = va.validateHTTP01(ctx, ident, chall)
	if prob == nil {
		t.Fatalf("Should have found the wrong token value.")
	}
	test.AssertEquals(t, prob.Type, probs.UnauthorizedProblem)
	test.AssertEquals(t, len(log.GetAllMatching(`\[AUDIT\] `)), 1)

	log.Clear()
	setChallengeToken(&chall, pathMoved)
	_, prob = va.validateHTTP01(ctx, ident, chall)
	if prob != nil {
		t.Fatalf("Failed to follow 301 redirect")
	}
	test.AssertEquals(t, len(log.GetAllMatching(`redirect from ".*/`+pathMoved+`" to ".*/`+pathValid+`"`)), 1)

	log.Clear()
	setChallengeToken(&chall, pathFound)
	_, prob = va.validateHTTP01(ctx, ident, chall)
	if prob != nil {
		t.Fatalf("Failed to follow 302 redirect")
	}
	test.AssertEquals(t, len(log.GetAllMatching(`redirect from ".*/`+pathFound+`" to ".*/`+pathMoved+`"`)), 1)
	test.AssertEquals(t, len(log.GetAllMatching(`redirect from ".*/`+pathMoved+`" to ".*/`+pathValid+`"`)), 1)

	ipIdentifier := core.AcmeIdentifier{Type: core.IdentifierType("ip"), Value: "127.0.0.1"}
	_, prob = va.validateHTTP01(ctx, ipIdentifier, chall)
	if prob == nil {
		t.Fatalf("IdentifierType IP shouldn't have worked.")
	}
	test.AssertEquals(t, prob.Type, probs.MalformedProblem)

	_, prob = va.validateHTTP01(ctx, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "always.invalid"}, chall)
	if prob == nil {
		t.Fatalf("Domain name is invalid.")
	}
	test.AssertEquals(t, prob.Type, probs.UnknownHostProblem)
}

func TestHTTPTimeout(t *testing.T) {
	chall := core.HTTPChallenge01()
	setChallengeToken(&chall, expectedToken)

	hs := httpSrv(t, chall.Token)
	// TODO(#1989): close hs

	va, _ := setup(hs)

	setChallengeToken(&chall, pathWaitLong)
	started := time.Now()
	_, prob := va.validateHTTP01(ctx, ident, chall)
	took := time.Since(started)
	// Check that the HTTP connection times out after 5 seconds and doesn't block for 10 seconds
	test.Assert(t, (took > (time.Second * 5)), "HTTP timed out before 5 seconds")
	test.Assert(t, (took < (time.Second * 10)), "HTTP connection didn't timeout after 5 seconds")
	if prob == nil {
		t.Fatalf("Connection should've timed out")
	}
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)
	expectMatch := regexp.MustCompile(
		"Fetching http://localhost:\\d+/.well-known/acme-challenge/wait-long: Timeout")
	if !expectMatch.MatchString(prob.Detail) {
		t.Errorf("Problem details incorrect. Got %q, expected to match %q",
			prob.Detail, expectMatch)
	}
}

func TestHTTPRedirectLookup(t *testing.T) {
	chall := core.HTTPChallenge01()
	setChallengeToken(&chall, expectedToken)

	hs := httpSrv(t, expectedToken)
	defer hs.Close()
	va, log := setup(hs)

	setChallengeToken(&chall, pathMoved)
	_, prob := va.validateHTTP01(ctx, ident, chall)
	if prob != nil {
		t.Fatalf("Unexpected failure in redirect (%s): %s", pathMoved, prob)
	}
	test.AssertEquals(t, len(log.GetAllMatching(`redirect from ".*/`+pathMoved+`" to ".*/`+pathValid+`"`)), 1)
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for localhost \[using 127.0.0.1\]: \[127.0.0.1\]`)), 2)

	log.Clear()
	setChallengeToken(&chall, pathFound)
	_, prob = va.validateHTTP01(ctx, ident, chall)
	if prob != nil {
		t.Fatalf("Unexpected failure in redirect (%s): %s", pathFound, prob)
	}
	test.AssertEquals(t, len(log.GetAllMatching(`redirect from ".*/`+pathFound+`" to ".*/`+pathMoved+`"`)), 1)
	test.AssertEquals(t, len(log.GetAllMatching(`redirect from ".*/`+pathMoved+`" to ".*/`+pathValid+`"`)), 1)
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for localhost \[using 127.0.0.1\]: \[127.0.0.1\]`)), 3)

	log.Clear()
	setChallengeToken(&chall, pathReLookupInvalid)
	_, err := va.validateHTTP01(ctx, ident, chall)
	test.AssertError(t, err, chall.Token)
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for localhost \[using 127.0.0.1\]: \[127.0.0.1\]`)), 1)
	test.AssertEquals(t, len(log.GetAllMatching(`No valid IP addresses found for invalid.invalid`)), 1)

	log.Clear()
	setChallengeToken(&chall, pathReLookup)
	_, prob = va.validateHTTP01(ctx, ident, chall)
	if prob != nil {
		t.Fatalf("Unexpected error in redirect (%s): %s", pathReLookup, prob)
	}
	test.AssertEquals(t, len(log.GetAllMatching(`redirect from ".*/`+pathReLookup+`" to ".*other.valid:\d+/path"`)), 1)
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for localhost \[using 127.0.0.1\]: \[127.0.0.1\]`)), 1)
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for other.valid \[using 127.0.0.1\]: \[127.0.0.1\]`)), 1)

	log.Clear()
	setChallengeToken(&chall, pathRedirectPort)
	_, err = va.validateHTTP01(ctx, ident, chall)
	test.AssertError(t, err, chall.Token)
	test.AssertEquals(t, len(log.GetAllMatching(`redirect from ".*/port-redirect" to ".*other.valid:8080/path"`)), 1)
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for localhost \[using 127.0.0.1\]: \[127.0.0.1\]`)), 1)
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for other.valid \[using 127.0.0.1\]: \[127.0.0.1\]`)), 1)

	// This case will redirect from a valid host to a host that is throwing
	// HTTP 500 errors. The test case is ensuring that the connection error
	// is referencing the redirected to host, instead of the original host.
	log.Clear()
	setChallengeToken(&chall, pathRedirectToFailingURL)
	_, prob = va.validateHTTP01(ctx, ident, chall)
	test.AssertNotNil(t, prob, "Problem Details should not be nil")
	test.AssertEquals(t, prob.Detail, "Fetching http://other.valid/500: Error getting validation data")
}

func TestHTTPRedirectLoop(t *testing.T) {
	chall := core.HTTPChallenge01()
	setChallengeToken(&chall, "looper")

	hs := httpSrv(t, expectedToken)
	defer hs.Close()
	va, _ := setup(hs)

	_, prob := va.validateHTTP01(ctx, ident, chall)
	if prob == nil {
		t.Fatalf("Challenge should have failed for %s", chall.Token)
	}
}

func TestHTTPRedirectUserAgent(t *testing.T) {
	chall := core.HTTPChallenge01()
	setChallengeToken(&chall, expectedToken)

	hs := httpSrv(t, expectedToken)
	defer hs.Close()
	va, _ := setup(hs)
	va.userAgent = rejectUserAgent

	setChallengeToken(&chall, pathMoved)
	_, prob := va.validateHTTP01(ctx, ident, chall)
	if prob == nil {
		t.Fatalf("Challenge with rejectUserAgent should have failed (%s).", pathMoved)
	}

	setChallengeToken(&chall, pathFound)
	_, prob = va.validateHTTP01(ctx, ident, chall)
	if prob == nil {
		t.Fatalf("Challenge with rejectUserAgent should have failed (%s).", pathFound)
	}
}

func getPort(hs *httptest.Server) int {
	url, err := url.Parse(hs.URL)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse hs URL: %q - %s", hs.URL, err.Error()))
	}
	_, portString, err := net.SplitHostPort(url.Host)
	if err != nil {
		panic(fmt.Sprintf("Failed to split hs URL host: %q - %s", url.Host, err.Error()))
	}
	port, err := strconv.ParseInt(portString, 10, 64)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse hs URL port: %q - %s", portString, err.Error()))
	}
	return int(port)
}

func TestTLSSNI01(t *testing.T) {
	chall := createChallenge(core.ChallengeTypeTLSSNI01)

	hs := tlssni01Srv(t, chall)

	va, log := setup(hs)

	_, prob := va.validateTLSSNI01(ctx, ident, chall)
	if prob != nil {
		t.Fatalf("Unexpected failure in validate TLS-SNI-01: %s", prob)
	}
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for localhost \[using 127.0.0.1\]: \[127.0.0.1\]`)), 1)
	if len(log.GetAllMatching(`challenge for localhost received certificate \(1 of 1\): cert=\[`)) != 1 {
		t.Errorf("Didn't get log message with validated certificate. Instead got:\n%s",
			strings.Join(log.GetAllMatching(".*"), "\n"))
	}

	log.Clear()
	port := getPort(hs)
	_, prob = va.validateTLSSNI01(ctx, core.AcmeIdentifier{
		Type:  core.IdentifierType("ip"),
		Value: net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)),
	}, chall)
	if prob == nil {
		t.Fatalf("IdentifierType IP shouldn't have worked.")
	}
	test.AssertEquals(t, prob.Type, probs.MalformedProblem)

	log.Clear()
	_, prob = va.validateTLSSNI01(ctx, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "always.invalid"}, chall)
	if prob == nil {
		t.Fatalf("Domain name was supposed to be invalid.")
	}
	test.AssertEquals(t, prob.Type, probs.UnknownHostProblem)

	// Need to create a new authorized keys object to get an unknown SNI (from the signature value)
	chall.Token = core.NewToken()
	chall.ProvidedKeyAuthorization = "invalid"

	log.Clear()
	started := time.Now()
	_, prob = va.validateTLSSNI01(ctx, ident, chall)
	took := time.Since(started)
	if prob == nil {
		t.Fatalf("Validation should've failed")
	}
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)
	// Check that the TLS connection times out after 5 seconds and doesn't block for 10 seconds
	test.Assert(t, (took > (time.Second * 5)), "TLS returned before 5 seconds")
	test.Assert(t, (took < (time.Second * 10)), "TLS connection didn't timeout after 5 seconds")
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for localhost \[using 127.0.0.1\]: \[127.0.0.1\]`)), 1)

	// Take down validation server and check that validation fails.
	hs.Close()
	_, err := va.validateTLSSNI01(ctx, ident, chall)
	if err == nil {
		t.Fatalf("Server's down; expected refusal. Where did we connect?")
	}
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)

	httpOnly := httpSrv(t, "")
	va.tlsPort = getPort(httpOnly)

	log.Clear()
	_, err = va.validateTLSSNI01(ctx, ident, chall)
	test.AssertError(t, err, "TLS-SNI-01 validation passed when talking to a HTTP-only server")
	test.Assert(t, strings.HasSuffix(
		err.Error(),
		"Server only speaks HTTP, not TLS",
	), "validate TLS-SNI-01 didn't return useful error")
}

func TestTLSSNI02(t *testing.T) {
	chall := createChallenge(core.ChallengeTypeTLSSNI02)

	hs := tlssni02Srv(t, chall)

	va, log := setup(hs)

	_, prob := va.validateTLSSNI02(ctx, ident, chall)
	if prob != nil {
		t.Fatalf("Unexpected failure in validate TLS-SNI-02: %s", prob)
	}
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for localhost \[using 127.0.0.1\]: \[127.0.0.1\]`)), 1)
	if len(log.GetAllMatching(`challenge for localhost received certificate \(1 of 1\): cert=\[`)) != 1 {
		t.Errorf("Didn't get log message with validated certificate. Instead got:\n%s",
			strings.Join(log.GetAllMatching(".*"), "\n"))
	}

	log.Clear()
	port := getPort(hs)
	_, prob = va.validateTLSSNI02(ctx, core.AcmeIdentifier{
		Type:  core.IdentifierType("ip"),
		Value: net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)),
	}, chall)
	if prob == nil {
		t.Fatalf("IdentifierType IP shouldn't have worked.")
	}
	test.AssertEquals(t, prob.Type, probs.MalformedProblem)

	log.Clear()
	_, prob = va.validateTLSSNI02(ctx, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "always.invalid"}, chall)
	if prob == nil {
		t.Fatalf("Domain name was supposed to be invalid.")
	}
	test.AssertEquals(t, prob.Type, probs.UnknownHostProblem)

	// Need to create a new authorized keys object to get an unknown SNI (from the signature value)
	chall.Token = core.NewToken()
	chall.ProvidedKeyAuthorization = "invalid"

	log.Clear()
	started := time.Now()
	_, prob = va.validateTLSSNI02(ctx, ident, chall)
	took := time.Since(started)
	if prob == nil {
		t.Fatalf("Validation should have failed")
	}
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)
	// Check that the TLS connection times out after 5 seconds and doesn't block for 10 seconds
	test.Assert(t, (took > (time.Second * 5)), "TLS returned before 5 seconds")
	test.Assert(t, (took < (time.Second * 10)), "TLS connection didn't timeout after 5 seconds")
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for localhost \[using 127.0.0.1\]: \[127.0.0.1\]`)), 1)

	// Take down validation server and check that validation fails.
	hs.Close()
	_, err := va.validateTLSSNI02(ctx, ident, chall)
	if err == nil {
		t.Fatalf("Server's down; expected refusal. Where did we connect?")
	}
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)

	httpOnly := httpSrv(t, "")
	defer httpOnly.Close()
	va.tlsPort = getPort(httpOnly)

	log.Clear()
	_, err = va.validateTLSSNI02(ctx, ident, chall)
	test.AssertError(t, err, "TLS-SNI-02 validation passed when talking to a HTTP-only server")
	test.Assert(t, strings.HasSuffix(
		err.Error(),
		"Server only speaks HTTP, not TLS",
	), "validate TLS-SNI-02 didn't return useful error")
}

func brokenTLSSrv() *httptest.Server {
	server := httptest.NewUnstartedServer(http.DefaultServeMux)
	server.TLS = &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, fmt.Errorf("Failing on purpose")
		},
	}
	server.StartTLS()
	return server
}

func TestTLSError(t *testing.T) {
	chall := createChallenge(core.ChallengeTypeTLSSNI01)
	hs := brokenTLSSrv()

	va, _ := setup(hs)

	_, prob := va.validateTLSSNI01(ctx, ident, chall)
	if prob == nil {
		t.Fatalf("TLS validation should have failed: What cert was used?")
	}
	if prob.Type != probs.TLSProblem {
		t.Errorf("Wrong problem type: got %s, expected type %s",
			prob, probs.TLSProblem)
	}
}

// misconfiguredTLSSrv is a TLS HTTP test server that returns a certificate
// chain with more than one cert, none of which will solve a TLS SNI challenge
func misconfiguredTLSSrv() *httptest.Server {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1337),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 1),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		Subject: pkix.Name{
			CommonName: "hello.world",
		},
		DNSNames: []string{"goodbye.world", "hello.world"},
	}

	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &TheKey.PublicKey, &TheKey)
	cert := &tls.Certificate{
		Certificate: [][]byte{certBytes, certBytes},
		PrivateKey:  &TheKey,
	}

	server := httptest.NewUnstartedServer(http.DefaultServeMux)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	server.StartTLS()
	return server
}

func TestCertNames(t *testing.T) {
	// We duplicate names inside the SAN set
	names := []string{
		"hello.world", "goodbye.world",
		"hello.world", "goodbye.world",
		"bonjour.le.monde", "au.revoir.le.monde",
		"bonjour.le.monde", "au.revoir.le.monde",
	}
	// We expect only unique names, in sorted order
	expected := []string{
		"au.revoir.le.monde", "bonjour.le.monde",
		"goodbye.world", "hello.world",
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1337),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 1),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		Subject: pkix.Name{
			// We also duplicate a name from the SANs as the CN
			CommonName: names[0],
		},
		DNSNames: names,
	}

	// Create the certificate, check that certNames provides the expected result
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &TheKey.PublicKey, &TheKey)
	cert, _ := x509.ParseCertificate(certBytes)
	actual := certNames(cert)
	test.AssertDeepEquals(t, actual, expected)
}

// TestSNIErrInvalidChain sets up a TLS server with two certificates, neither of
// which validate the SNI challenge.
func TestSNIErrInvalidChain(t *testing.T) {
	chall := createChallenge(core.ChallengeTypeTLSSNI01)
	hs := misconfiguredTLSSrv()

	va, _ := setup(hs)

	// Validate the SNI challenge with the test server, expecting it to fail
	_, prob := va.validateTLSSNI01(ctx, ident, chall)
	if prob == nil {
		t.Fatalf("TLS validation should have failed")
	}

	// We expect that the error message will say 2 certificates were received, and
	// we expect the error to contain a deduplicated list of domain names from the
	// subject CN and SANs of the leaf cert
	expected := "Received 2 certificate(s), first certificate had names \"goodbye.world, hello.world\""
	test.AssertEquals(t, prob.Type, probs.UnauthorizedProblem)
	test.AssertContains(t, prob.Detail, expected)
}

func TestValidateHTTP(t *testing.T) {
	chall := core.HTTPChallenge01()
	setChallengeToken(&chall, core.NewToken())

	hs := httpSrv(t, chall.Token)
	defer hs.Close()

	va, _ := setup(hs)

	_, prob := va.validateChallenge(ctx, ident, chall)
	test.Assert(t, prob == nil, "validation failed")
}

// challengeType == "tls-sni-00" or "dns-00", since they're the same
func createChallenge(challengeType string) core.Challenge {
	chall := core.Challenge{
		Type:                     challengeType,
		Status:                   core.StatusPending,
		Token:                    expectedToken,
		ValidationRecord:         []core.ValidationRecord{},
		ProvidedKeyAuthorization: expectedKeyAuthorization,
	}

	return chall
}

// setChallengeToken sets the token value, and sets the ProvidedKeyAuthorization
// to match.
func setChallengeToken(ch *core.Challenge, token string) {
	ch.Token = token
	ch.ProvidedKeyAuthorization = token + ".9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI"
}

func TestValidateTLSSNI01(t *testing.T) {
	chall := createChallenge(core.ChallengeTypeTLSSNI01)
	hs := tlssni01Srv(t, chall)
	defer hs.Close()

	va, _ := setup(hs)

	_, prob := va.validateChallenge(ctx, ident, chall)

	test.Assert(t, prob == nil, "validation failed")
}

func TestValidateTLSSNI01NotSane(t *testing.T) {
	va, _ := setup(nil)

	chall := createChallenge(core.ChallengeTypeTLSSNI01)

	chall.Token = "not sane"

	_, prob := va.validateChallenge(ctx, ident, chall)

	test.AssertEquals(t, prob.Type, probs.MalformedProblem)
}

func TestCAATimeout(t *testing.T) {
	va, _ := setup(nil)
	err := va.checkCAA(ctx, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "caa-timeout.com"})
	if err.Type != probs.ConnectionProblem {
		t.Errorf("Expected timeout error type %s, got %s", probs.ConnectionProblem, err.Type)
	}
	expected := "DNS problem: query timed out looking up CAA for always.timeout"
	if err.Detail != expected {
		t.Errorf("checkCAA: got %#v, expected %#v", err.Detail, expected)
	}
}

func TestCAAChecking(t *testing.T) {
	type CAATest struct {
		Domain  string
		Present bool
		Valid   bool
	}
	tests := []CAATest{
		// Reserved
		{"reserved.com", true, false},
		// Critical
		{"critical.com", true, false},
		{"nx.critical.com", true, false},
		// Good (absent)
		{"absent.com", false, true},
		{"example.co.uk", false, true},
		// Good (present)
		{"present.com", true, true},
		{"present.servfail.com", true, true},
		// Good (multiple critical, one matching)
		{"multi-crit-present.com", true, true},
		// Bad (unknown critical)
		{"unknown-critical.com", true, false},
		{"unknown-critical2.com", true, false},
		// Good (unknown noncritical, no issue/issuewild records)
		{"unknown-noncritical.com", true, true},
		// Good (issue record with unknown parameters)
		{"present-with-parameter.com", true, true},
		// Bad (unsatisfiable issue record)
		{"unsatisfiable.com", true, false},
	}

	va, _ := setup(nil)
	for _, caaTest := range tests {
		present, valid, err := va.checkCAARecords(ctx, core.AcmeIdentifier{Type: "dns", Value: caaTest.Domain})
		if err != nil {
			t.Errorf("checkCAARecords error for %s: %s", caaTest.Domain, err)
		}
		if present != caaTest.Present {
			t.Errorf("checkCAARecords presence mismatch for %s: got %t expected %t", caaTest.Domain, present, caaTest.Present)
		}
		if valid != caaTest.Valid {
			t.Errorf("checkCAARecords validity mismatch for %s: got %t expected %t", caaTest.Domain, valid, caaTest.Valid)
		}
	}

	present, valid, err := va.checkCAARecords(ctx, core.AcmeIdentifier{Type: "dns", Value: "servfail.com"})
	test.AssertError(t, err, "servfail.com")
	test.Assert(t, !present, "Present should be false")
	test.Assert(t, !valid, "Valid should be false")

	_, _, err = va.checkCAARecords(ctx, core.AcmeIdentifier{Type: "dns", Value: "servfail.com"})
	if err == nil {
		t.Errorf("Should have returned error on CAA lookup, but did not: %s", "servfail.com")
	}

	present, valid, err = va.checkCAARecords(ctx, core.AcmeIdentifier{Type: "dns", Value: "servfail.present.com"})
	test.AssertError(t, err, "servfail.present.com")
	test.Assert(t, !present, "Present should be false")
	test.Assert(t, !valid, "Valid should be false")

	_, _, err = va.checkCAARecords(ctx, core.AcmeIdentifier{Type: "dns", Value: "servfail.present.com"})
	if err == nil {
		t.Errorf("Should have returned error on CAA lookup, but did not: %s", "servfail.present.com")
	}
}

func TestPerformValidationInvalid(t *testing.T) {
	va, _ := setup(nil)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockScope := mock_metrics.NewMockScope(ctrl)
	va.stats = mockScope
	mockScope.EXPECT().TimingDuration("Validations.dns-01.invalid", gomock.Any()).Return(nil)
	mockScope.EXPECT().Inc(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	chalDNS := createChallenge(core.ChallengeTypeDNS01)
	_, prob := va.PerformValidation(context.Background(), "foo.com", chalDNS, core.Authorization{})
	test.Assert(t, prob != nil, "validation succeeded")
}

func TestDNSValidationEmpty(t *testing.T) {
	va, _ := setup(nil)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockScope := mock_metrics.NewMockScope(ctrl)
	va.stats = mockScope
	mockScope.EXPECT().TimingDuration("Validations.dns-01.invalid", gomock.Any()).Return(nil)
	mockScope.EXPECT().Inc(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	chalDNS := createChallenge(core.ChallengeTypeDNS01)
	_, prob := va.PerformValidation(
		context.Background(),
		"empty-txts.com",
		chalDNS,
		core.Authorization{})
	test.AssertEquals(t, prob.Error(), "urn:acme:error:unauthorized :: No TXT records found for DNS challenge")
}

func TestPerformValidationValid(t *testing.T) {
	va, _ := setup(nil)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockScope := mock_metrics.NewMockScope(ctrl)
	va.stats = mockScope
	mockScope.EXPECT().TimingDuration("Validations.dns-01.valid", gomock.Any()).Return(nil)
	mockScope.EXPECT().Inc(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	// create a challenge with well known token
	chalDNS := core.DNSChallenge01()
	chalDNS.Token = expectedToken
	chalDNS.ProvidedKeyAuthorization = expectedKeyAuthorization
	_, prob := va.PerformValidation(context.Background(), "good-dns01.com", chalDNS, core.Authorization{})
	test.Assert(t, prob == nil, fmt.Sprintf("validation failed: %#v", prob))
}

func TestDNSValidationFailure(t *testing.T) {
	va, _ := setup(nil)

	chalDNS := createChallenge(core.ChallengeTypeDNS01)

	_, prob := va.validateChallenge(ctx, ident, chalDNS)

	test.AssertEquals(t, prob.Type, probs.UnauthorizedProblem)
}

func TestDNSValidationInvalid(t *testing.T) {
	var notDNS = core.AcmeIdentifier{
		Type:  core.IdentifierType("iris"),
		Value: "790DB180-A274-47A4-855F-31C428CB1072",
	}

	chalDNS := core.DNSChallenge01()
	chalDNS.ProvidedKeyAuthorization = expectedKeyAuthorization

	va, _ := setup(nil)

	_, prob := va.validateChallenge(ctx, notDNS, chalDNS)

	test.AssertEquals(t, prob.Type, probs.MalformedProblem)
}

func TestDNSValidationNotSane(t *testing.T) {
	va, _ := setup(nil)

	chal0 := core.DNSChallenge01()
	chal0.Token = ""

	chal1 := core.DNSChallenge01()
	chal1.Token = "yfCBb-bRTLz8Wd1C0lTUQK3qlKj3-t2tYGwx5Hj7r_"

	chal2 := core.DNSChallenge01()
	chal2.ProvidedKeyAuthorization = ""

	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     ident,
		Challenges:     []core.Challenge{chal0, chal1, chal2},
	}

	for i := 0; i < len(authz.Challenges); i++ {
		_, prob := va.validateChallenge(ctx, ident, authz.Challenges[i])
		if prob.Type != probs.MalformedProblem {
			t.Errorf("Got wrong error type for %d: expected %s, got %s",
				i, prob.Type, probs.MalformedProblem)
		}
		if !strings.Contains(prob.Error(), "Challenge failed consistency check:") {
			t.Errorf("Got wrong error: %s", prob.Error())
		}
	}
}

func TestDNSValidationServFail(t *testing.T) {
	va, _ := setup(nil)

	chalDNS := createChallenge(core.ChallengeTypeDNS01)

	badIdent := core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: "servfail.com",
	}
	_, prob := va.validateChallenge(ctx, badIdent, chalDNS)

	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)
}

func TestDNSValidationNoServer(t *testing.T) {
	va, _ := setup(nil)
	va.dnsResolver = bdns.NewTestDNSResolverImpl(
		time.Second*5,
		nil,
		metrics.NewNoopScope(),
		clock.Default(),
		1)

	chalDNS := createChallenge(core.ChallengeTypeDNS01)

	_, prob := va.validateChallenge(ctx, ident, chalDNS)

	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)
}

func TestDNSValidationOK(t *testing.T) {
	va, _ := setup(nil)

	// create a challenge with well known token
	chalDNS := core.DNSChallenge01()
	chalDNS.Token = expectedToken
	chalDNS.ProvidedKeyAuthorization = expectedKeyAuthorization

	goodIdent := core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: "good-dns01.com",
	}

	_, prob := va.validateChallenge(ctx, goodIdent, chalDNS)

	test.Assert(t, prob == nil, "Should be valid.")
}

func TestDNSValidationNoAuthorityOK(t *testing.T) {
	va, _ := setup(nil)

	// create a challenge with well known token
	chalDNS := core.DNSChallenge01()
	chalDNS.Token = expectedToken

	chalDNS.ProvidedKeyAuthorization = expectedKeyAuthorization

	goodIdent := core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: "no-authority-dns01.com",
	}

	_, prob := va.validateChallenge(ctx, goodIdent, chalDNS)

	test.Assert(t, prob == nil, "Should be valid.")
}

func TestCAAFailure(t *testing.T) {
	chall := createChallenge(core.ChallengeTypeTLSSNI01)
	hs := tlssni01Srv(t, chall)
	defer hs.Close()

	va, _ := setup(hs)

	ident.Value = "reserved.com"
	_, prob := va.validateChallengeAndCAA(ctx, ident, chall)
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)
}

func TestLimitedReader(t *testing.T) {
	chall := core.HTTPChallenge01()
	setChallengeToken(&chall, core.NewToken())

	ident.Value = "localhost"
	hs := httpSrv(t, "01234567890123456789012345678901234567890123456789012345678901234567890123456789")
	va, _ := setup(hs)
	defer hs.Close()

	_, prob := va.validateChallenge(ctx, ident, chall)

	test.AssertEquals(t, prob.Type, probs.UnauthorizedProblem)
	test.Assert(t, strings.HasPrefix(prob.Detail, "Invalid response from "),
		"Expected failure due to truncation")
}

func setup(srv *httptest.Server) (*ValidationAuthorityImpl, *blog.Mock) {
	logger := blog.NewMock()

	var portConfig cmd.PortConfig
	if srv != nil {
		port := getPort(srv)
		portConfig = cmd.PortConfig{
			HTTPPort: port,
			TLSPort:  port,
		}
	}
	va := NewValidationAuthorityImpl(
		// Use the test server's port as both the HTTPPort and the TLSPort for the VA
		&portConfig,
		nil,
		&bdns.MockDNSResolver{},
		"user agent 1.0",
		"letsencrypt.org",
		metrics.NewNoopScope(),
		clock.Default(),
		logger)
	return va, logger
}

func TestParseResults(t *testing.T) {
	r := []caaResult{}
	s, err := parseResults(r)
	test.Assert(t, s == nil, "set is not nil")
	test.Assert(t, err == nil, "error is not nil")
	test.AssertNotError(t, err, "no error should be returned")
	r = []caaResult{{nil, errors.New("")}, {[]*dns.CAA{{Value: "test"}}, nil}}
	s, err = parseResults(r)
	test.Assert(t, s == nil, "set is not nil")
	test.AssertEquals(t, err.Error(), "")
	expected := dns.CAA{Value: "other-test"}
	r = []caaResult{{[]*dns.CAA{&expected}, nil}, {[]*dns.CAA{{Value: "test"}}, nil}}
	s, err = parseResults(r)
	test.AssertEquals(t, len(s.Unknown), 1)
	test.Assert(t, s.Unknown[0] == &expected, "Incorrect record returned")
	test.AssertNotError(t, err, "no error should be returned")
}

func TestAvailableAddresses(t *testing.T) {
	v6a := net.ParseIP("::1")
	v6b := net.ParseIP("2001:db8::2:1") // 2001:DB8 is reserved for docs (RFC 3849)
	v4a := net.ParseIP("127.0.0.1")
	v4b := net.ParseIP("192.0.2.1") // 192.0.2.0/24 is reserved for docs (RFC 5737)

	testcases := []struct {
		input core.ValidationRecord
		v4    []net.IP
		v6    []net.IP
	}{
		// An empty validation record
		{
			core.ValidationRecord{},
			[]net.IP{},
			[]net.IP{},
		},
		// A validation record with one IPv4 address
		{
			core.ValidationRecord{
				AddressesResolved: []net.IP{v4a},
			},
			[]net.IP{v4a},
			[]net.IP{},
		},
		// A dual homed record with an IPv4 and IPv6 address
		{
			core.ValidationRecord{
				AddressesResolved: []net.IP{v4a, v6a},
			},
			[]net.IP{v4a},
			[]net.IP{v6a},
		},
		// The same as above but with the v4/v6 order flipped
		{
			core.ValidationRecord{
				AddressesResolved: []net.IP{v6a, v4a},
			},
			[]net.IP{v4a},
			[]net.IP{v6a},
		},
		// A validation record with just IPv6 addresses
		{
			core.ValidationRecord{
				AddressesResolved: []net.IP{v6a, v6b},
			},
			[]net.IP{},
			[]net.IP{v6a, v6b},
		},
		// A validation record with interleaved IPv4/IPv6 records
		{
			core.ValidationRecord{
				AddressesResolved: []net.IP{v6a, v4a, v6b, v4b},
			},
			[]net.IP{v4a, v4b},
			[]net.IP{v6a, v6b},
		},
	}

	for _, tc := range testcases {
		// Split the input record into v4/v6 addresses
		v4result, v6result := availableAddresses(tc.input)

		// Test that we got the right number of v4 results
		test.Assert(t, len(tc.v4) == len(v4result),
			fmt.Sprintf("Wrong # of IPv4 results: expected %d, got %d", len(tc.v4), len(v4result)))

		// Check that all of the v4 results match expected values
		for i, v4addr := range tc.v4 {
			test.Assert(t, v4addr.String() == v4result[i].String(),
				fmt.Sprintf("Wrong v4 result index %d: expected %q got %q", i, v4addr.String(), v4result[i].String()))
		}

		// Test that we got the right number of v6 results
		test.Assert(t, len(tc.v6) == len(v6result),
			fmt.Sprintf("Wrong # of IPv6 results: expected %d, got %d", len(tc.v6), len(v6result)))

		// Check that all of the v6 results match expected values
		for i, v6addr := range tc.v6 {
			test.Assert(t, v6addr.String() == v6result[i].String(),
				fmt.Sprintf("Wrong v6 result index %d: expected %q got %q", i, v6addr.String(), v6result[i].String()))
		}
	}
}

func TestFallbackDialer(t *testing.T) {
	// Create a new challenge to use for the httpSrv
	chall := core.HTTPChallenge01()
	setChallengeToken(&chall, core.NewToken())

	// Create an IPv4 test server
	hs := httpSrv(t, chall.Token)
	defer hs.Close()

	// Create a test VA
	va, _ := setup(hs)

	// Create an identifier for a host that has an IPv6 and an IPv4 address.
	// Since the IPv6First feature flag is not enabled we expect that the IPv4
	// address will be used and validation will succeed using the httpSrv we
	// created earlier.
	host := "ipv4.and.ipv6.localhost"
	ident = core.AcmeIdentifier{Type: core.IdentifierDNS, Value: host}
	records, prob := va.validateChallenge(ctx, ident, chall)
	test.Assert(t, prob == nil, "validation failed for an dual homed host with IPv6First disabled")
	// We expect one validation record to be present
	test.AssertEquals(t, len(records), 1)
	// We expect that the address used was the IPv4 address
	test.AssertEquals(t, records[0].AddressUsed.String(), "127.0.0.1")
	// We expect that zero addresses were tried before the address used
	test.AssertEquals(t, len(records[0].AddressesTried), 0)

	// Enable the IPv6 First feature
	_ = features.Set(map[string]bool{"IPv6First": true})
	defer features.Reset()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	scope := mock_metrics.NewMockScope(ctrl)
	va.stats = scope

	// We expect the IPV4 Fallback stat to be incremented
	scope.EXPECT().Inc("IPv4Fallback", int64(1)).Return(nil)

	// The validation is expected to succeed with IPv6First enabled even though
	// the V6 server doesn't exist because we fallback to the IPv4 address.
	records, prob = va.validateChallenge(ctx, ident, chall)
	test.Assert(t, prob == nil, "validation failed with IPv6 fallback to IPv4")
	// We expect one validation record to be present
	test.AssertEquals(t, len(records), 1)
	// We expect that the address used was the IPv4 localhost address
	test.AssertEquals(t, records[0].AddressUsed.String(), "127.0.0.1")
	// We expect that one address was tried before the address used
	test.AssertEquals(t, len(records[0].AddressesTried), 1)
	// We expect that IPv6 address was tried before the address used
	test.AssertEquals(t, records[0].AddressesTried[0].String(), "::1")
}

func TestFallbackTLS(t *testing.T) {
	// Create a new challenge to use for the httpSrv
	chall := createChallenge(core.ChallengeTypeTLSSNI01)

	// Create a TLS SNI 01 test server, this will be bound on 127.0.0.1 (e.g. IPv4
	// only!)
	hs := tlssni01Srv(t, chall)
	defer hs.Close()

	// Create a test VA
	va, _ := setup(hs)

	// Create an identifier for a host that has an IPv6 and an IPv4 address.
	// Since the IPv6First feature flag is not enabled we expect that the IPv4
	// address will be used and validation will succeed using the httpSrv we
	// created earlier.
	host := "ipv4.and.ipv6.localhost"
	ident = core.AcmeIdentifier{Type: core.IdentifierDNS, Value: host}
	records, prob := va.validateChallenge(ctx, ident, chall)
	test.Assert(t, prob == nil, "validation failed for a dual-homed address with an IPv4 server")
	// We expect one validation record to be present
	test.AssertEquals(t, len(records), 1)
	// We expect that the address used was the IPv4 localhost address
	test.AssertEquals(t, records[0].AddressUsed.String(), "127.0.0.1")
	// We expect that no addresses were tried before the address used
	test.AssertEquals(t, len(records[0].AddressesTried), 0)

	// Enable the IPv6 First feature
	_ = features.Set(map[string]bool{"IPv6First": true})
	defer features.Reset()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	scope := mock_metrics.NewMockScope(ctrl)
	va.stats = scope

	// We expect the IPV4 Fallback stat to be incremented
	scope.EXPECT().Inc("IPv4Fallback", int64(1)).Return(nil)

	// The validation is expected to succeed now that IPv6First is enabled by the
	// fallback to the IPv4 address that has a test server waiting
	records, prob = va.validateChallenge(ctx, ident, chall)
	test.Assert(t, prob == nil, "validation failed with IPv6 fallback to IPv4")
	// We expect one validation record to be present
	test.AssertEquals(t, len(records), 1)
	// We expect that the address eventually used was the IPv4 localhost address
	test.AssertEquals(t, records[0].AddressUsed.String(), "127.0.0.1")
	// We expect that one address was tried before the address used
	test.AssertEquals(t, len(records[0].AddressesTried), 1)
	// We expect that IPv6 localhost address was tried before the address used
	test.AssertEquals(t, records[0].AddressesTried[0].String(), "::1")

	// Now try a validation for an IPv6 only host. E.g. one without an IPv4
	// address. The IPv6 will fail without a server and we expect the overall
	// validation to fail since there is no IPv4 address/listener to fall back to.
	host = "ipv6.localhost"
	ident = core.AcmeIdentifier{Type: core.IdentifierDNS, Value: host}
	va.stats = metrics.NewNoopScope()
	records, prob = va.validateChallenge(ctx, ident, chall)

	// The validation is expected to fail since there is no IPv4 to fall back to
	// and a broken IPv6
	records, prob = va.validateChallenge(ctx, ident, chall)
	test.Assert(t, prob != nil, "validation succeeded with broken IPv6 and no IPv4 fallback")
	// We expect that the problem has the correct error message about working IPs
	test.AssertEquals(t, prob.Detail, "no working IP addresses found for \"ipv6.localhost\"")
	// We expect one validation record to be present
	test.AssertEquals(t, len(records), 1)
	// We expect that the address eventually used was the IPv6 localhost address
	test.AssertEquals(t, records[0].AddressUsed.String(), "::1")
	// We expect that one address was tried
	test.AssertEquals(t, len(records[0].AddressesTried), 1)
	// We expect that IPv6 localhost address was tried
	test.AssertEquals(t, records[0].AddressesTried[0].String(), "::1")
}
