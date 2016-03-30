// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

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

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/golang.org/x/net/context"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/probs"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/mocks"
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

var log = mocks.UseMockLog()

// All paths that get assigned to tokens MUST be valid tokens
const expectedToken = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
const pathWrongToken = "i6lNAC4lOOLYCl-A08VJt9z_tKYvVk63Dumo8icsBjQ"
const path404 = "404"
const pathFound = "GBq8SwWq3JsbREFdCamk5IX3KLsxW5ULeGs98Ajl_UM"
const pathMoved = "5J4FIMrWNfmvHZo-QpKZngmuhqZGwRm21-oEgUDstJM"
const pathRedirectPort = "port-redirect"
const pathWait = "wait"
const pathWaitLong = "wait-long"
const pathReLookup = "7e-P57coLM7D3woNTp_xbJrtlkDYy6PWf3mSSbLwCr4"
const pathReLookupInvalid = "re-lookup-invalid"
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

			keyAuthz, _ := core.NewKeyAuthorization(currentToken, accountKey)
			t.Logf("HTTPSRV: Key Authz = '%s%s'\n", keyAuthz.String(), "\\n\\r \\t")

			fmt.Fprint(w, keyAuthz.String(), "\n\r \t")
			currentToken = defaultToken
		}
	})

	server.Start()
	return server
}

func tlssniSrv(t *testing.T, chall core.Challenge) *httptest.Server {
	h := sha256.New()
	h.Write([]byte(chall.KeyAuthorization.String()))
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
	chall := core.HTTPChallenge01(accountKey)
	err := setChallengeToken(&chall, expectedToken)
	test.AssertNotError(t, err, "Failed to complete HTTP challenge")

	// NOTE: We do not attempt to shut down the server. The problem is that the
	// "wait-long" handler sleeps for ten seconds, but this test finishes in less
	// than that. So if we try to call hs.Close() at the end of the test, we'll be
	// closing the test server while a request is still pending. Unfortunately,
	// there appears to be an issue in httptest that trips Go's race detector when
	// that happens, failing the test. So instead, we live with leaving the server
	// around till the process exits.
	// TODO(#661): add hs.Close back, see ticket for blocker
	hs := httpSrv(t, chall.Token)

	goodPort, err := getPort(hs)
	test.AssertNotError(t, err, "failed to get test server port")

	// Attempt to fail a challenge by telling the VA to connect to a port we are
	// not listening on.
	badPort := goodPort + 1
	if badPort == 65536 {
		badPort = goodPort - 1
	}
	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{HTTPPort: badPort}, nil, stats, clock.Default())
	va.DNSResolver = &bdns.MockDNSResolver{}

	_, prob := va.validateHTTP01(context.Background(), ident, chall)
	if prob == nil {
		t.Fatalf("Server's down; expected refusal. Where did we connect?")
	}
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)

	va = NewValidationAuthorityImpl(&PortConfig{HTTPPort: goodPort}, nil, stats, clock.Default())
	va.DNSResolver = &bdns.MockDNSResolver{}

	log.Clear()
	t.Logf("Trying to validate: %+v\n", chall)
	_, prob = va.validateHTTP01(context.Background(), ident, chall)
	if prob != nil {
		t.Errorf("Unexpected failure in HTTP validation: %s", prob)
	}
	test.AssertEquals(t, len(log.GetAllMatching(`^\[AUDIT\] `)), 1)

	log.Clear()
	setChallengeToken(&chall, path404)
	_, prob = va.validateHTTP01(context.Background(), ident, chall)
	if prob == nil {
		t.Fatalf("Should have found a 404 for the challenge.")
	}
	test.AssertEquals(t, prob.Type, probs.UnauthorizedProblem)
	test.AssertEquals(t, len(log.GetAllMatching(`^\[AUDIT\] `)), 1)

	log.Clear()
	setChallengeToken(&chall, pathWrongToken)
	// The "wrong token" will actually be the expectedToken.  It's wrong
	// because it doesn't match pathWrongToken.
	_, prob = va.validateHTTP01(context.Background(), ident, chall)
	if prob == nil {
		t.Fatalf("Should have found the wrong token value.")
	}
	test.AssertEquals(t, prob.Type, probs.UnauthorizedProblem)
	test.AssertEquals(t, len(log.GetAllMatching(`^\[AUDIT\] `)), 1)

	log.Clear()
	setChallengeToken(&chall, pathMoved)
	_, prob = va.validateHTTP01(context.Background(), ident, chall)
	if prob != nil {
		t.Fatalf("Failed to follow 301 redirect")
	}
	test.AssertEquals(t, len(log.GetAllMatching(`redirect from ".*/`+pathMoved+`" to ".*/`+pathValid+`"`)), 1)

	log.Clear()
	setChallengeToken(&chall, pathFound)
	_, prob = va.validateHTTP01(context.Background(), ident, chall)
	if prob != nil {
		t.Fatalf("Failed to follow 302 redirect")
	}
	test.AssertEquals(t, len(log.GetAllMatching(`redirect from ".*/`+pathFound+`" to ".*/`+pathMoved+`"`)), 1)
	test.AssertEquals(t, len(log.GetAllMatching(`redirect from ".*/`+pathMoved+`" to ".*/`+pathValid+`"`)), 1)

	ipIdentifier := core.AcmeIdentifier{Type: core.IdentifierType("ip"), Value: "127.0.0.1"}
	_, prob = va.validateHTTP01(context.Background(), ipIdentifier, chall)
	if prob == nil {
		t.Fatalf("IdentifierType IP shouldn't have worked.")
	}
	test.AssertEquals(t, prob.Type, probs.MalformedProblem)

	_, prob = va.validateHTTP01(context.Background(), core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "always.invalid"}, chall)
	if prob == nil {
		t.Fatalf("Domain name is invalid.")
	}
	test.AssertEquals(t, prob.Type, probs.UnknownHostProblem)

	setChallengeToken(&chall, pathWaitLong)
	started := time.Now()
	_, prob = va.validateHTTP01(context.Background(), ident, chall)
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
	chall := core.HTTPChallenge01(accountKey)
	err := setChallengeToken(&chall, expectedToken)
	test.AssertNotError(t, err, "Failed to complete HTTP challenge")

	hs := httpSrv(t, expectedToken)
	defer hs.Close()
	port, err := getPort(hs)
	test.AssertNotError(t, err, "failed to get test server port")
	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{HTTPPort: port}, nil, stats, clock.Default())
	va.DNSResolver = &bdns.MockDNSResolver{}

	log.Clear()
	setChallengeToken(&chall, pathMoved)
	_, prob := va.validateHTTP01(context.Background(), ident, chall)
	if prob != nil {
		t.Fatalf("Unexpected failure in redirect (%s): %s", pathMoved, prob)
	}
	test.AssertEquals(t, len(log.GetAllMatching(`redirect from ".*/`+pathMoved+`" to ".*/`+pathValid+`"`)), 1)
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for localhost \[using 127.0.0.1\]: \[127.0.0.1\]`)), 2)

	log.Clear()
	setChallengeToken(&chall, pathFound)
	_, prob = va.validateHTTP01(context.Background(), ident, chall)
	if prob != nil {
		t.Fatalf("Unexpected failure in redirect (%s): %s", pathFound, prob)
	}
	test.AssertEquals(t, len(log.GetAllMatching(`redirect from ".*/`+pathFound+`" to ".*/`+pathMoved+`"`)), 1)
	test.AssertEquals(t, len(log.GetAllMatching(`redirect from ".*/`+pathMoved+`" to ".*/`+pathValid+`"`)), 1)
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for localhost \[using 127.0.0.1\]: \[127.0.0.1\]`)), 3)

	log.Clear()
	setChallengeToken(&chall, pathReLookupInvalid)
	_, err = va.validateHTTP01(context.Background(), ident, chall)
	test.AssertError(t, err, chall.Token)
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for localhost \[using 127.0.0.1\]: \[127.0.0.1\]`)), 1)
	test.AssertEquals(t, len(log.GetAllMatching(`No IPv4 addresses found for invalid.invalid`)), 1)

	log.Clear()
	setChallengeToken(&chall, pathReLookup)
	_, prob = va.validateHTTP01(context.Background(), ident, chall)
	if prob != nil {
		t.Fatalf("Unexpected error in redirect (%s): %s", pathReLookup, prob)
	}
	test.AssertEquals(t, len(log.GetAllMatching(`redirect from ".*/`+pathReLookup+`" to ".*other.valid:\d+/path"`)), 1)
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for localhost \[using 127.0.0.1\]: \[127.0.0.1\]`)), 1)
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for other.valid \[using 127.0.0.1\]: \[127.0.0.1\]`)), 1)

	log.Clear()
	setChallengeToken(&chall, pathRedirectPort)
	_, err = va.validateHTTP01(context.Background(), ident, chall)
	test.AssertError(t, err, chall.Token)
	test.AssertEquals(t, len(log.GetAllMatching(`redirect from ".*/port-redirect" to ".*other.valid:8080/path"`)), 1)
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for localhost \[using 127.0.0.1\]: \[127.0.0.1\]`)), 1)
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for other.valid \[using 127.0.0.1\]: \[127.0.0.1\]`)), 1)
}

func TestHTTPRedirectLoop(t *testing.T) {
	chall := core.HTTPChallenge01(accountKey)
	err := setChallengeToken(&chall, "looper")
	test.AssertNotError(t, err, "Failed to complete HTTP challenge")

	hs := httpSrv(t, expectedToken)
	defer hs.Close()
	port, err := getPort(hs)
	test.AssertNotError(t, err, "failed to get test server port")
	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{HTTPPort: port}, nil, stats, clock.Default())
	va.DNSResolver = &bdns.MockDNSResolver{}

	log.Clear()
	_, prob := va.validateHTTP01(context.Background(), ident, chall)
	if prob == nil {
		t.Fatalf("Challenge should have failed for %s", chall.Token)
	}
}

func TestHTTPRedirectUserAgent(t *testing.T) {
	chall := core.HTTPChallenge01(accountKey)
	err := setChallengeToken(&chall, expectedToken)
	test.AssertNotError(t, err, "Failed to complete HTTP challenge")

	hs := httpSrv(t, expectedToken)
	defer hs.Close()
	port, err := getPort(hs)
	test.AssertNotError(t, err, "failed to get test server port")
	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{HTTPPort: port}, nil, stats, clock.Default())
	va.DNSResolver = &bdns.MockDNSResolver{}
	va.UserAgent = rejectUserAgent

	setChallengeToken(&chall, pathMoved)
	_, prob := va.validateHTTP01(context.Background(), ident, chall)
	if prob == nil {
		t.Fatalf("Challenge with rejectUserAgent should have failed (%s).", pathMoved)
	}

	setChallengeToken(&chall, pathFound)
	_, prob = va.validateHTTP01(context.Background(), ident, chall)
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

	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{TLSPort: port}, nil, stats, clock.Default())

	va.DNSResolver = &bdns.MockDNSResolver{}

	log.Clear()
	_, prob := va.validateTLSSNI01(context.Background(), ident, chall)
	if prob != nil {
		t.Fatalf("Unexpected failre in validateTLSSNI01: %s", prob)
	}
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for localhost \[using 127.0.0.1\]: \[127.0.0.1\]`)), 1)

	log.Clear()
	_, prob = va.validateTLSSNI01(context.Background(), core.AcmeIdentifier{
		Type:  core.IdentifierType("ip"),
		Value: net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)),
	}, chall)
	if prob == nil {
		t.Fatalf("IdentifierType IP shouldn't have worked.")
	}
	test.AssertEquals(t, prob.Type, probs.MalformedProblem)

	log.Clear()
	_, prob = va.validateTLSSNI01(context.Background(), core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "always.invalid"}, chall)
	if prob == nil {
		t.Fatalf("Domain name was supposed to be invalid.")
	}
	test.AssertEquals(t, prob.Type, probs.UnknownHostProblem)

	// Need to create a new authorized keys object to get an unknown SNI (from the signature value)
	chall.Token = core.NewToken()
	keyAuthorization, _ := core.NewKeyAuthorization(chall.Token, accountKey)
	chall.KeyAuthorization = &keyAuthorization

	log.Clear()
	started := time.Now()
	_, prob = va.validateTLSSNI01(context.Background(), ident, chall)
	took := time.Since(started)
	// Check that the HTTP connection times out after 5 seconds and doesn't block for 10 seconds
	test.Assert(t, (took > (time.Second * 5)), "HTTP timed out before 5 seconds")
	test.Assert(t, (took < (time.Second * 10)), "HTTP connection didn't timeout after 5 seconds")
	if prob == nil {
		t.Fatalf("Connection should've timed out")
	}
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)
	test.AssertEquals(t, len(log.GetAllMatching(`Resolved addresses for localhost \[using 127.0.0.1\]: \[127.0.0.1\]`)), 1)

	// Take down validation server and check that validation fails.
	hs.Close()
	_, err = va.validateTLSSNI01(context.Background(), ident, chall)
	if err == nil {
		t.Fatalf("Server's down; expected refusal. Where did we connect?")
	}
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)
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
	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{TLSPort: port}, nil, stats, clock.Default())
	va.DNSResolver = &bdns.MockDNSResolver{}

	_, prob := va.validateTLSSNI01(context.Background(), ident, chall)
	if prob == nil {
		t.Fatalf("TLS validation should have failed: What cert was used?")
	}
	test.AssertEquals(t, prob.Type, probs.TLSProblem)
}

func TestValidateHTTP(t *testing.T) {
	chall := core.HTTPChallenge01(accountKey)
	err := setChallengeToken(&chall, core.NewToken())
	test.AssertNotError(t, err, "Failed to complete HTTP challenge")

	hs := httpSrv(t, chall.Token)
	port, err := getPort(hs)
	test.AssertNotError(t, err, "failed to get test server port")
	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{HTTPPort: port}, nil, stats, clock.Default())
	va.DNSResolver = &bdns.MockDNSResolver{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	defer hs.Close()

	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     ident,
		Challenges:     []core.Challenge{chall},
	}
	va.validate(context.Background(), authz, 0)

	test.AssertEquals(t, core.StatusValid, mockRA.lastAuthz.Challenges[0].Status)
}

// challengeType == "tls-sni-00" or "dns-00", since they're the same
func createChallenge(challengeType string) core.Challenge {
	chall := core.Challenge{
		Type:             challengeType,
		Status:           core.StatusPending,
		Token:            core.NewToken(),
		ValidationRecord: []core.ValidationRecord{},
		AccountKey:       accountKey,
	}

	keyAuthorization, _ := core.NewKeyAuthorization(chall.Token, accountKey)
	chall.KeyAuthorization = &keyAuthorization

	return chall
}

// setChallengeToken sets the token value both in the Token field and
// in the serialized KeyAuthorization object.
func setChallengeToken(ch *core.Challenge, token string) (err error) {
	ch.Token = token

	keyAuthorization, err := core.NewKeyAuthorization(token, ch.AccountKey)
	if err != nil {
		return
	}

	ch.KeyAuthorization = &keyAuthorization
	return
}

func TestValidateTLSSNI01(t *testing.T) {
	chall := createChallenge(core.ChallengeTypeTLSSNI01)
	hs := tlssniSrv(t, chall)
	defer hs.Close()

	port, err := getPort(hs)
	test.AssertNotError(t, err, "failed to get test server port")

	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{TLSPort: port}, nil, stats, clock.Default())
	va.DNSResolver = &bdns.MockDNSResolver{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     ident,
		Challenges:     []core.Challenge{chall},
	}
	va.validate(context.Background(), authz, 0)

	test.AssertEquals(t, core.StatusValid, mockRA.lastAuthz.Challenges[0].Status)
}

func TestValidateTLSSNINotSane(t *testing.T) {
	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{}, nil, stats, clock.Default()) // no calls made
	va.DNSResolver = &bdns.MockDNSResolver{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	chall := createChallenge(core.ChallengeTypeTLSSNI01)

	chall.Token = "not sane"

	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     ident,
		Challenges:     []core.Challenge{chall},
	}
	va.validate(context.Background(), authz, 0)

	test.AssertEquals(t, core.StatusInvalid, mockRA.lastAuthz.Challenges[0].Status)
}

func TestUpdateValidations(t *testing.T) {
	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{}, nil, stats, clock.Default())
	va.DNSResolver = &bdns.MockDNSResolver{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	chall := core.HTTPChallenge01(accountKey)
	chall.ValidationRecord = []core.ValidationRecord{}
	err := setChallengeToken(&chall, core.NewToken())
	test.AssertNotError(t, err, "Failed to complete HTTP challenge")

	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     ident,
		Challenges:     []core.Challenge{chall},
	}

	started := time.Now()
	va.UpdateValidations(authz, 0)
	took := time.Since(started)

	// Check that the call to va.UpdateValidations didn't block for 3 seconds
	test.Assert(t, (took < (time.Second * 3)), "UpdateValidations blocked")
}

func TestCAATimeout(t *testing.T) {
	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{}, nil, stats, clock.Default())
	va.DNSResolver = &bdns.MockDNSResolver{}
	va.IssuerDomain = "letsencrypt.org"
	err := va.checkCAA(context.Background(), core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "caa-timeout.com"})
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

	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{}, nil, stats, clock.Default())
	va.DNSResolver = &bdns.MockDNSResolver{}
	va.IssuerDomain = "letsencrypt.org"
	for _, caaTest := range tests {
		present, valid, err := va.checkCAARecords(context.Background(), core.AcmeIdentifier{Type: "dns", Value: caaTest.Domain})
		if err != nil {
			t.Errorf("CheckCAARecords error for %s: %s", caaTest.Domain, err)
		}
		if present != caaTest.Present {
			t.Errorf("CheckCAARecords presence mismatch for %s: got %t expected %t", caaTest.Domain, present, caaTest.Present)
		}
		if valid != caaTest.Valid {
			t.Errorf("CheckCAARecords presence mismatch for %s: got %t expected %t", caaTest.Domain, valid, caaTest.Valid)
		}
	}

	present, valid, err := va.checkCAARecords(context.Background(), core.AcmeIdentifier{Type: "dns", Value: "servfail.com"})
	test.AssertError(t, err, "servfail.com")
	test.Assert(t, !present, "Present should be false")
	test.Assert(t, !valid, "Valid should be false")

	_, _, err = va.checkCAARecords(context.Background(), core.AcmeIdentifier{Type: "dns", Value: "servfail.com"})
	if err == nil {
		t.Errorf("Should have returned error on CAA lookup, but did not: %s", "servfail.com")
	}

	present, valid, err = va.checkCAARecords(context.Background(), core.AcmeIdentifier{Type: "dns", Value: "servfail.present.com"})
	test.AssertError(t, err, "servfail.present.com")
	test.Assert(t, !present, "Present should be false")
	test.Assert(t, !valid, "Valid should be false")

	_, _, err = va.checkCAARecords(context.Background(), core.AcmeIdentifier{Type: "dns", Value: "servfail.present.com"})
	if err == nil {
		t.Errorf("Should have returned error on CAA lookup, but did not: %s", "servfail.present.com")
	}
}

func TestDNSValidationFailure(t *testing.T) {
	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{}, nil, stats, clock.Default())
	va.DNSResolver = &bdns.MockDNSResolver{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	chalDNS := createChallenge(core.ChallengeTypeDNS01)

	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     ident,
		Challenges:     []core.Challenge{chalDNS},
	}
	va.validate(context.Background(), authz, 0)

	t.Logf("Resulting Authz: %+v", authz)
	test.AssertNotNil(t, mockRA.lastAuthz, "Should have gotten an authorization")
	test.Assert(t, authz.Challenges[0].Status == core.StatusInvalid, "Should be invalid.")
	test.AssertEquals(t, authz.Challenges[0].Error.Type, probs.UnauthorizedProblem)
}

func TestDNSValidationInvalid(t *testing.T) {
	var notDNS = core.AcmeIdentifier{
		Type:  core.IdentifierType("iris"),
		Value: "790DB180-A274-47A4-855F-31C428CB1072",
	}

	chalDNS := core.DNSChallenge01(accountKey)

	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     notDNS,
		Challenges:     []core.Challenge{chalDNS},
	}

	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{}, nil, stats, clock.Default())
	va.DNSResolver = &bdns.MockDNSResolver{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	va.validate(context.Background(), authz, 0)

	test.AssertNotNil(t, mockRA.lastAuthz, "Should have gotten an authorization")
	test.Assert(t, authz.Challenges[0].Status == core.StatusInvalid, "Should be invalid.")
	test.AssertEquals(t, authz.Challenges[0].Error.Type, probs.MalformedProblem)
}

func TestDNSValidationNotSane(t *testing.T) {
	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{}, nil, stats, clock.Default())
	va.DNSResolver = &bdns.MockDNSResolver{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	chal0 := core.DNSChallenge01(accountKey)
	chal0.Token = ""

	chal1 := core.DNSChallenge01(accountKey)
	chal1.Token = "yfCBb-bRTLz8Wd1C0lTUQK3qlKj3-t2tYGwx5Hj7r_"

	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     ident,
		Challenges:     []core.Challenge{chal0, chal1},
	}

	for i := 0; i < len(authz.Challenges); i++ {
		va.validate(context.Background(), authz, i)
		test.AssertEquals(t, authz.Challenges[i].Status, core.StatusInvalid)
		test.AssertEquals(t, authz.Challenges[i].Error.Type, probs.MalformedProblem)
	}
}

func TestDNSValidationServFail(t *testing.T) {
	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{}, nil, stats, clock.Default())
	va.DNSResolver = &bdns.MockDNSResolver{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	chalDNS := createChallenge(core.ChallengeTypeDNS01)

	badIdent := core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: "servfail.com",
	}
	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     badIdent,
		Challenges:     []core.Challenge{chalDNS},
	}
	va.validate(context.Background(), authz, 0)

	test.AssertNotNil(t, mockRA.lastAuthz, "Should have gotten an authorization")
	test.Assert(t, authz.Challenges[0].Status == core.StatusInvalid, "Should be invalid.")
	test.AssertEquals(t, authz.Challenges[0].Error.Type, probs.ConnectionProblem)
}

func TestDNSValidationNoServer(t *testing.T) {
	c, _ := statsd.NewNoopClient()
	stats := metrics.NewNoopScope()
	va := NewValidationAuthorityImpl(&PortConfig{}, nil, c, clock.Default())
	va.DNSResolver = bdns.NewTestDNSResolverImpl(time.Second*5, []string{}, stats, clock.Default(), 1)
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	chalDNS := createChallenge(core.ChallengeTypeDNS01)

	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     ident,
		Challenges:     []core.Challenge{chalDNS},
	}
	va.validate(context.Background(), authz, 0)

	test.AssertNotNil(t, mockRA.lastAuthz, "Should have gotten an authorization")
	test.Assert(t, authz.Challenges[0].Status == core.StatusInvalid, "Should be invalid.")
	test.AssertEquals(t, authz.Challenges[0].Error.Type, probs.ConnectionProblem)
}

func TestDNSValidationOK(t *testing.T) {
	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{}, nil, stats, clock.Default())
	va.DNSResolver = &bdns.MockDNSResolver{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	// create a challenge with well known token
	chalDNS := core.DNSChallenge01(accountKey)
	chalDNS.Token = expectedToken

	keyAuthorization, _ := core.NewKeyAuthorization(chalDNS.Token, accountKey)
	chalDNS.KeyAuthorization = &keyAuthorization

	goodIdent := core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: "good-dns01.com",
	}

	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     goodIdent,
		Challenges:     []core.Challenge{chalDNS},
	}
	va.validate(context.Background(), authz, 0)

	test.AssertNotNil(t, mockRA.lastAuthz, "Should have gotten an authorization")
	test.Assert(t, authz.Challenges[0].Status == core.StatusValid, "Should be valid.")
}

func TestDNSValidationNoAuthorityOK(t *testing.T) {
	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{}, nil, stats, clock.Default())
	va.DNSResolver = &bdns.MockDNSResolver{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	// create a challenge with well known token
	chalDNS := core.DNSChallenge01(accountKey)
	chalDNS.Token = expectedToken

	keyAuthorization, _ := core.NewKeyAuthorization(chalDNS.Token, accountKey)
	chalDNS.KeyAuthorization = &keyAuthorization

	goodIdent := core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: "no-authority-dns01.com",
	}

	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     goodIdent,
		Challenges:     []core.Challenge{chalDNS},
	}
	va.validate(context.Background(), authz, 0)

	test.AssertNotNil(t, mockRA.lastAuthz, "Should have gotten an authorization")
	test.Assert(t, authz.Challenges[0].Status == core.StatusValid, "Should be valid.")
}

// TestDNSValidationLive is an integration test, depending on
// the existence of some Internet resources. Because of that,
// it asserts nothing; it is intended for coverage.
func TestDNSValidationLive(t *testing.T) {
	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{}, nil, stats, clock.Default())
	va.DNSResolver = &bdns.MockDNSResolver{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	goodChalDNS := core.DNSChallenge01(accountKey)
	// The matching value LPsIwTo7o8BoG0-vjCyGQGBWSVIPxI-i_X336eUOQZo
	// is set at _acme-challenge.good.bin.coffee
	goodChalDNS.Token = expectedToken

	var goodIdent = core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: "good.bin.coffee",
	}

	var badIdent = core.AcmeIdentifier{
		Type:  core.IdentifierType("dns"),
		Value: "bad.bin.coffee",
	}

	var authzGood = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     goodIdent,
		Challenges:     []core.Challenge{goodChalDNS},
	}

	va.validate(context.Background(), authzGood, 0)

	if authzGood.Challenges[0].Status != core.StatusValid {
		t.Logf("TestDNSValidationLive on Good did not succeed.")
	}

	badChalDNS := core.DNSChallenge01(accountKey)
	// The matching value is NOT set at _acme-challenge.bad.bin.coffee
	badChalDNS.Token = "yfCBb-bRTLz8Wd1C0lTUQK3qlKj3-t2tYGwx5Hj7r_w"

	var authzBad = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     badIdent,
		Challenges:     []core.Challenge{badChalDNS},
	}

	va.validate(context.Background(), authzBad, 0)
	if authzBad.Challenges[0].Status != core.StatusInvalid {
		t.Logf("TestDNSValidationLive on Bad did succeed inappropriately.")
	}
}

func TestCAAFailure(t *testing.T) {
	chall := createChallenge(core.ChallengeTypeTLSSNI01)
	hs := tlssniSrv(t, chall)
	defer hs.Close()

	port, err := getPort(hs)
	test.AssertNotError(t, err, "failed to get test server port")

	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&PortConfig{TLSPort: port}, nil, stats, clock.Default())
	va.DNSResolver = &bdns.MockDNSResolver{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	ident.Value = "reserved.com"
	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     ident,
		Challenges:     []core.Challenge{chall},
	}
	va.validate(context.Background(), authz, 0)

	test.AssertEquals(t, core.StatusInvalid, mockRA.lastAuthz.Challenges[0].Status)
}

type MockRegistrationAuthority struct {
	lastAuthz *core.Authorization
}

func (ra *MockRegistrationAuthority) NewRegistration(reg core.Registration) (core.Registration, error) {
	return reg, nil
}

func (ra *MockRegistrationAuthority) NewAuthorization(authz core.Authorization, regID int64) (core.Authorization, error) {
	return authz, nil
}

func (ra *MockRegistrationAuthority) NewCertificate(req core.CertificateRequest, regID int64) (core.Certificate, error) {
	return core.Certificate{}, nil
}

func (ra *MockRegistrationAuthority) UpdateRegistration(reg core.Registration, updated core.Registration) (core.Registration, error) {
	return reg, nil
}

func (ra *MockRegistrationAuthority) UpdateAuthorization(authz core.Authorization, foo int, challenge core.Challenge) (core.Authorization, error) {
	return authz, nil
}

func (ra *MockRegistrationAuthority) RevokeCertificateWithReg(cert x509.Certificate, reason core.RevocationCode, reg int64) error {
	return nil
}

func (ra *MockRegistrationAuthority) AdministrativelyRevokeCertificate(cert x509.Certificate, reason core.RevocationCode, user string) error {
	return nil
}

func (ra *MockRegistrationAuthority) OnValidationUpdate(authz core.Authorization) error {
	ra.lastAuthz = &authz
	return nil
}
