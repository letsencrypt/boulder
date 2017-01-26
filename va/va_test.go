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
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
	"gopkg.in/square/go-jose.v1"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cdr"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/mocks"
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
		if !strings.HasPrefix(r.Host, "localhost:") && !strings.HasPrefix(r.Host, "other.valid:") {
			t.Errorf("Bad Host header: " + r.Host)
		}
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
			port, err := getPort(server)
			test.AssertNotError(t, err, "failed to get server test port")
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

func tlssniSrv(t *testing.T, chall core.Challenge) *httptest.Server {
	h := sha256.New()
	h.Write([]byte(chall.ProvidedKeyAuthorization))
	Z := hex.EncodeToString(h.Sum(nil))
	ZName := fmt.Sprintf("%s.%s.acme.invalid", Z[:32], Z[32:])

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

		DNSNames: []string{ZName},
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
			if clientHello.ServerName != ZName {
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

	goodPort, err := getPort(hs)
	test.AssertNotError(t, err, "failed to get test server port")

	// Attempt to fail a challenge by telling the VA to connect to a port we are
	// not listening on.
	badPort := goodPort + 1
	if badPort == 65536 {
		badPort = goodPort - 1
	}
	va, _, log := setup()
	va.httpPort = badPort

	_, prob := va.validateHTTP01(ctx, ident, chall)
	if prob == nil {
		t.Fatalf("Server's down; expected refusal. Where did we connect?")
	}
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)

	va.httpPort = goodPort
	log.Clear()
	t.Logf("Trying to validate: %+v\n", chall)
	_, prob = va.validateHTTP01(ctx, ident, chall)
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

	setChallengeToken(&chall, pathWaitLong)
	started := time.Now()
	_, prob = va.validateHTTP01(ctx, ident, chall)
	took := time.Since(started)
	// Check that the HTTP connection times out after 5 seconds and doesn't block for 10 seconds
	test.Assert(t, (took > (time.Second * 5)), "HTTP timed out before 5 seconds")
	test.Assert(t, (took < (time.Second * 10)), "HTTP connection didn't timeout after 5 seconds")
	if prob == nil {
		t.Fatalf("Connection should've timed out")
	}
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)
}

func TestHTTPRedirectLookup(t *testing.T) {
	chall := core.HTTPChallenge01()
	setChallengeToken(&chall, expectedToken)

	hs := httpSrv(t, expectedToken)
	defer hs.Close()
	port, err := getPort(hs)
	test.AssertNotError(t, err, "failed to get test server port")
	va, _, log := setup()
	va.httpPort = port

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
	_, err = va.validateHTTP01(ctx, ident, chall)
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
	test.AssertEquals(t, prob.Detail, "Could not connect to other.valid")
}

func TestHTTPRedirectLoop(t *testing.T) {
	chall := core.HTTPChallenge01()
	setChallengeToken(&chall, "looper")

	hs := httpSrv(t, expectedToken)
	defer hs.Close()
	port, err := getPort(hs)
	test.AssertNotError(t, err, "failed to get test server port")
	va, _, _ := setup()
	va.httpPort = port

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
	port, err := getPort(hs)
	test.AssertNotError(t, err, "failed to get test server port")
	va, _, _ := setup()
	va.userAgent = rejectUserAgent
	va.httpPort = port

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

func getPort(hs *httptest.Server) (int, error) {
	url, err := url.Parse(hs.URL)
	if err != nil {
		return 0, err
	}
	_, portString, err := net.SplitHostPort(url.Host)
	if err != nil {
		return 0, err
	}
	port, err := strconv.ParseInt(portString, 10, 64)
	if err != nil {
		return 0, err
	}
	return int(port), nil
}

func TestTLSSNI(t *testing.T) {
	chall := createChallenge(core.ChallengeTypeTLSSNI01)

	hs := tlssniSrv(t, chall)
	port, err := getPort(hs)
	test.AssertNotError(t, err, "failed to get test server port")

	va, _, log := setup()
	va.tlsPort = port

	_, prob := va.validateTLSSNI01(ctx, ident, chall)
	if prob != nil {
		t.Fatalf("Unexpected failure in validateTLSSNI01: %s", prob)
	}
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for localhost \[using 127.0.0.1\]: \[127.0.0.1\]`)), 1)
	if len(log.GetAllMatching(`challenge for localhost received certificate \(1 of 1\): cert=\[`)) != 1 {
		t.Errorf("Didn't get log message with validated certificate. Instead got:\n%s",
			strings.Join(log.GetAllMatching(".*"), "\n"))
	}

	log.Clear()
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
	_, err = va.validateTLSSNI01(ctx, ident, chall)
	if err == nil {
		t.Fatalf("Server's down; expected refusal. Where did we connect?")
	}
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)

	httpOnly := httpSrv(t, "")
	defer httpOnly.Close()
	port, err = getPort(httpOnly)
	test.AssertNotError(t, err, "failed to get test server port")
	va.tlsPort = port

	log.Clear()
	_, err = va.validateTLSSNI01(ctx, ident, chall)
	test.AssertError(t, err, "TLS SNI validation passed when talking to a HTTP-only server")
	test.Assert(t, strings.HasSuffix(
		err.Error(),
		"Server only speaks HTTP, not TLS",
	), "validateTLSSNI01 didn't return useful error")
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

	port, err := getPort(hs)
	test.AssertNotError(t, err, "failed to get test server port")
	va, _, _ := setup()
	va.tlsPort = port

	_, prob := va.validateTLSSNI01(ctx, ident, chall)
	if prob == nil {
		t.Fatalf("TLS validation should have failed: What cert was used?")
	}
	test.AssertEquals(t, prob.Type, probs.TLSProblem)
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

// TestSNIErrInvalidChain sets up a TLS server with two certificates, neither of
// which validate the SNI challenge.
func TestSNIErrInvalidChain(t *testing.T) {
	chall := createChallenge(core.ChallengeTypeTLSSNI01)
	hs := misconfiguredTLSSrv()

	port, err := getPort(hs)
	test.AssertNotError(t, err, "failed to get test server port")
	va, _, _ := setup()
	va.tlsPort = port

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
	port, err := getPort(hs)
	test.AssertNotError(t, err, "failed to get test server port")
	va, _, _ := setup()
	va.httpPort = port

	defer hs.Close()

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
	hs := tlssniSrv(t, chall)
	defer hs.Close()

	port, err := getPort(hs)
	test.AssertNotError(t, err, "failed to get test server port")

	va, _, _ := setup()
	va.tlsPort = port

	_, prob := va.validateChallenge(ctx, ident, chall)

	test.Assert(t, prob == nil, "validation failed")
}

func TestValidateTLSSNINotSane(t *testing.T) {
	va, _, _ := setup()

	chall := createChallenge(core.ChallengeTypeTLSSNI01)

	chall.Token = "not sane"

	_, prob := va.validateChallenge(ctx, ident, chall)

	test.AssertEquals(t, prob.Type, probs.MalformedProblem)
}

func TestCAATimeout(t *testing.T) {
	va, _, _ := setup()
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

	va, _, _ := setup()
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
	va, stats, _ := setup()
	chalDNS := createChallenge(core.ChallengeTypeDNS01)
	_, prob := va.PerformValidation(context.Background(), "foo.com", chalDNS, core.Authorization{})
	test.Assert(t, prob != nil, "validation succeeded")
	test.AssertEquals(t, stats.TimingDurationCalls[0].Metric, "VA.Validations.dns-01.invalid")
}

func TestDNSValidationEmpty(t *testing.T) {
	va, stats, _ := setup()
	chalDNS := createChallenge(core.ChallengeTypeDNS01)
	_, prob := va.PerformValidation(
		context.Background(),
		"empty-txts.com",
		chalDNS,
		core.Authorization{})
	test.AssertEquals(t, prob.Error(), "urn:acme:error:unauthorized :: No TXT records found for DNS challenge")
	test.AssertEquals(t, stats.TimingDurationCalls[0].Metric, "VA.Validations.dns-01.invalid")
}

func TestPerformValidationValid(t *testing.T) {
	va, stats, _ := setup()
	// create a challenge with well known token
	chalDNS := core.DNSChallenge01()
	chalDNS.Token = expectedToken
	chalDNS.ProvidedKeyAuthorization = expectedKeyAuthorization
	_, prob := va.PerformValidation(context.Background(), "good-dns01.com", chalDNS, core.Authorization{})
	test.Assert(t, prob == nil, fmt.Sprintf("validation failed: %#v", prob))
	test.AssertEquals(t, stats.TimingDurationCalls[0].Metric, "VA.Validations.dns-01.valid")
}

func TestDNSValidationFailure(t *testing.T) {
	va, _, _ := setup()

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

	va, _, _ := setup()

	_, prob := va.validateChallenge(ctx, notDNS, chalDNS)

	test.AssertEquals(t, prob.Type, probs.MalformedProblem)
}

func TestDNSValidationNotSane(t *testing.T) {
	va, _, _ := setup()

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
		if !strings.Contains(prob.Error(), "Challenge failed sanity check.") {
			t.Errorf("Got wrong error: %s", prob.Error())
		}
	}
}

func TestDNSValidationServFail(t *testing.T) {
	va, _, _ := setup()

	chalDNS := createChallenge(core.ChallengeTypeDNS01)

	badIdent := core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: "servfail.com",
	}
	_, prob := va.validateChallenge(ctx, badIdent, chalDNS)

	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)
}

func TestDNSValidationNoServer(t *testing.T) {
	va, _, _ := setup()
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
	va, _, _ := setup()

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
	va, _, _ := setup()

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
	hs := tlssniSrv(t, chall)
	defer hs.Close()

	port, err := getPort(hs)
	test.AssertNotError(t, err, "failed to get test server port")

	va, _, _ := setup()
	va.tlsPort = port

	ident.Value = "reserved.com"
	_, prob := va.validateChallengeAndCAA(ctx, ident, chall)
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)
}

func TestLimitedReader(t *testing.T) {
	chall := core.HTTPChallenge01()
	setChallengeToken(&chall, core.NewToken())

	ident.Value = "localhost"
	hs := httpSrv(t, "01234567890123456789012345678901234567890123456789012345678901234567890123456789")
	port, err := getPort(hs)
	test.AssertNotError(t, err, "failed to get test server port")
	va, _, _ := setup()
	va.httpPort = port

	defer hs.Close()

	_, prob := va.validateChallenge(ctx, ident, chall)

	test.AssertEquals(t, prob.Type, probs.UnauthorizedProblem)
	test.Assert(t, strings.HasPrefix(prob.Detail, "Invalid response from "),
		"Expected failure due to truncation")
}

func setup() (*ValidationAuthorityImpl, *mocks.Statter, *blog.Mock) {
	stats := mocks.NewStatter()
	scope := metrics.NewStatsdScope(stats, "VA")
	logger := blog.NewMock()
	va := NewValidationAuthorityImpl(
		&cmd.PortConfig{},
		nil,
		nil,
		&bdns.MockDNSResolver{},
		"user agent 1.0",
		"letsencrypt.org",
		scope,
		clock.Default(),
		logger)
	return va, stats, logger
}

func TestCheckCAAFallback(t *testing.T) {
	testSrv := httptest.NewServer(http.HandlerFunc(mocks.GPDNSHandler))
	defer testSrv.Close()

	stats := mocks.NewStatter()
	scope := metrics.NewStatsdScope(stats, "VA")
	logger := blog.NewMock()
	caaDR, err := cdr.New(metrics.NewNoopScope(), time.Second, 1, nil, blog.NewMock())
	test.AssertNotError(t, err, "Failed to create CAADistributedResolver")
	caaDR.URI = testSrv.URL
	caaDR.Clients["1.1.1.1"] = new(http.Client)
	va := NewValidationAuthorityImpl(
		&cmd.PortConfig{},
		nil,
		caaDR,
		&bdns.MockDNSResolver{},
		"user agent 1.0",
		"ca.com",
		scope,
		clock.Default(),
		logger)

	prob := va.checkCAA(ctx, core.AcmeIdentifier{Value: "bad-local-resolver.com", Type: "dns"})
	test.Assert(t, prob == nil, fmt.Sprintf("returned ProblemDetails was non-nil: %#v", prob))

	va.caaDR = nil
	prob = va.checkCAA(ctx, core.AcmeIdentifier{Value: "bad-local-resolver.com", Type: "dns"})
	test.Assert(t, prob != nil, "returned ProblemDetails was nil")
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)
	test.AssertEquals(t, prob.Detail, "server failure at resolver")
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
