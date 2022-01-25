package va

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"
	"github.com/prometheus/client_golang/prometheus"
)

func tlsalpnChallenge() core.Challenge {
	return createChallenge(core.ChallengeTypeTLSALPN01)
}

func tlsCertTemplate(names []string) *x509.Certificate {
	return &x509.Certificate{
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
}

func makeACert(names []string) *tls.Certificate {
	template := tlsCertTemplate(names)
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &TheKey.PublicKey, &TheKey)
	return &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  &TheKey,
	}
}

// tlssniSrvWithNames is kept around for the use of TestValidateTLSALPN01UnawareSrv
func tlssniSrvWithNames(t *testing.T, chall core.Challenge, names ...string) *httptest.Server {
	cert := makeACert(names)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		ClientAuth:   tls.NoClientCert,
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return cert, nil
		},
		NextProtos: []string{"http/1.1"},
	}

	hs := httptest.NewUnstartedServer(http.DefaultServeMux)
	hs.TLS = tlsConfig
	hs.StartTLS()
	return hs
}

func tlsalpn01SrvWithCert(
	t *testing.T,
	chall core.Challenge,
	oid asn1.ObjectIdentifier,
	names []string,
	cert *tls.Certificate,
	acmeCert *tls.Certificate,
	tlsVersion uint16) *httptest.Server {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{},
		ClientAuth:   tls.NoClientCert,
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if clientHello.ServerName != names[0] {
				return nil, nil
			}
			if len(clientHello.SupportedProtos) == 1 && clientHello.SupportedProtos[0] == ACMETLS1Protocol {
				return acmeCert, nil
			}
			return cert, nil
		},
		NextProtos: []string{"http/1.1", ACMETLS1Protocol},
		MinVersion: tlsVersion,
		MaxVersion: tlsVersion,
	}

	hs := httptest.NewUnstartedServer(http.DefaultServeMux)
	hs.TLS = tlsConfig
	hs.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
		ACMETLS1Protocol: func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
			_ = conn.Close()
		},
	}
	hs.StartTLS()
	return hs
}

func tlsalpn01Srv(
	t *testing.T,
	chall core.Challenge,
	oid asn1.ObjectIdentifier,
	tlsVersion uint16,
	names ...string) (*httptest.Server, error) {
	template := tlsCertTemplate(names)
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &TheKey.PublicKey, &TheKey)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  &TheKey,
	}

	shasum := sha256.Sum256([]byte(chall.ProvidedKeyAuthorization))
	encHash, err := asn1.Marshal(shasum[:])
	if err != nil {
		return nil, err
	}
	acmeExtension := pkix.Extension{
		Id:       oid,
		Critical: true,
		Value:    encHash,
	}
	template.ExtraExtensions = []pkix.Extension{acmeExtension}
	certBytes, err = x509.CreateCertificate(rand.Reader, template, template, &TheKey.PublicKey, &TheKey)
	if err != nil {
		return nil, err
	}
	acmeCert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  &TheKey,
	}

	return tlsalpn01SrvWithCert(t, chall, oid, names, cert, acmeCert, tlsVersion), nil
}

func TestTLSALPN01FailIP(t *testing.T) {
	chall := tlsalpnChallenge()
	hs, err := tlsalpn01Srv(t, chall, IdPeAcmeIdentifier, 0, "localhost")
	test.AssertNotError(t, err, "Error creating test server")

	va, _ := setup(hs, 0, "", nil)

	port := getPort(hs)
	_, prob := va.validateTLSALPN01(ctx, identifier.ACMEIdentifier{
		Type:  identifier.IdentifierType("ip"),
		Value: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
	}, chall)
	if prob == nil {
		t.Fatalf("IdentifierType IP shouldn't have worked.")
	}
	test.AssertEquals(t, prob.Type, probs.MalformedProblem)
}

func slowTLSSrv() *httptest.Server {
	server := httptest.NewUnstartedServer(http.DefaultServeMux)
	server.TLS = &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			time.Sleep(100 * time.Millisecond)
			return makeACert([]string{"nomatter"}), nil
		},
	}
	server.StartTLS()
	return server
}

func TestTLSALPNTimeoutAfterConnect(t *testing.T) {
	chall := tlsalpnChallenge()
	hs := slowTLSSrv()
	va, _ := setup(hs, 0, "", nil)

	timeout := 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	started := time.Now()
	_, prob := va.validateTLSALPN01(ctx, dnsi("slow.server"), chall)
	if prob == nil {
		t.Fatalf("Validation should've failed")
	}
	// Check that the TLS connection doesn't return before a timeout, and times
	// out after the expected time
	took := time.Since(started)
	// Check that the HTTP connection doesn't return too fast, and times
	// out after the expected time
	if took < timeout/2 {
		t.Fatalf("TLSSNI returned before %s (%s) with %#v", timeout, took, prob)
	}
	if took > 2*timeout {
		t.Fatalf("TLSSNI didn't timeout after %s (took %s to return %#v)", timeout,
			took, prob)
	}
	if prob == nil {
		t.Fatalf("Connection should've timed out")
	}
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)
	expected := "Timeout during read (your server may be slow or overloaded)"
	if prob.Detail != expected {
		t.Errorf("Wrong error detail. Expected %q, got %q", expected, prob.Detail)
	}
}

func TestTLSALPN01DialTimeout(t *testing.T) {
	chall := tlsalpnChallenge()
	hs := slowTLSSrv()
	va, _ := setup(hs, 0, "", nil)
	va.dnsClient = dnsMockReturnsUnroutable{&bdns.MockClient{}}
	started := time.Now()

	timeout := 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// The only method I've found so far to trigger a connect timeout is to
	// connect to an unrouteable IP address. This usually generates a connection
	// timeout, but will rarely return "Network unreachable" instead. If we get
	// that, just retry until we get something other than "Network unreachable".
	var prob *probs.ProblemDetails
	for i := 0; i < 20; i++ {
		_, prob = va.validateTLSALPN01(ctx, dnsi("unroutable.invalid"), chall)
		if prob != nil && strings.Contains(prob.Detail, "Network unreachable") {
			continue
		} else {
			break
		}
	}

	if prob == nil {
		t.Fatalf("Validation should've failed")
	}
	// Check that the TLS connection doesn't return before a timeout, and times
	// out after the expected time
	took := time.Since(started)
	// Check that the HTTP connection doesn't return too fast, and times
	// out after the expected time
	if took < timeout/2 {
		t.Fatalf("TLSSNI returned before %s (%s) with %#v", timeout, took, prob)
	}
	if took > 2*timeout {
		t.Fatalf("TLSSNI didn't timeout after %s", timeout)
	}
	if prob == nil {
		t.Fatalf("Connection should've timed out")
	}
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)
	expected := "Timeout during connect (likely firewall problem)"
	if prob.Detail != expected {
		t.Errorf("Wrong error detail. Expected %q, got %q", expected, prob.Detail)
	}
}

func TestTLSALPN01Refused(t *testing.T) {
	chall := tlsalpnChallenge()
	hs, err := tlsalpn01Srv(t, chall, IdPeAcmeIdentifier, 0, "localhost")
	test.AssertNotError(t, err, "Error creating test server")

	va, _ := setup(hs, 0, "", nil)
	// Take down validation server and check that validation fails.
	hs.Close()
	_, prob := va.validateTLSALPN01(ctx, dnsi("localhost"), chall)
	if prob == nil {
		t.Fatalf("Server's down; expected refusal. Where did we connect?")
	}
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)
	expected := "Connection refused"
	if prob.Detail != expected {
		t.Errorf("Wrong error detail. Expected %q, got %q", expected, prob.Detail)
	}
}

func TestTLSALPN01TalkingToHTTP(t *testing.T) {
	chall := tlsalpnChallenge()
	hs, err := tlsalpn01Srv(t, chall, IdPeAcmeIdentifier, 0, "localhost")
	test.AssertNotError(t, err, "Error creating test server")

	va, _ := setup(hs, 0, "", nil)
	httpOnly := httpSrv(t, "")
	va.tlsPort = getPort(httpOnly)

	_, prob := va.validateTLSALPN01(ctx, dnsi("localhost"), chall)
	test.AssertError(t, prob, "TLS-SNI-01 validation passed when talking to a HTTP-only server")
	expected := "Server only speaks HTTP, not TLS"
	if !strings.HasSuffix(prob.Detail, expected) {
		t.Errorf("Got wrong error detail. Expected %q, got %q", expected, prob.Detail)
	}
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
	chall := tlsalpnChallenge()
	hs := brokenTLSSrv()

	va, _ := setup(hs, 0, "", nil)

	_, prob := va.validateTLSALPN01(ctx, dnsi("localhost"), chall)
	if prob == nil {
		t.Fatalf("TLS validation should have failed: What cert was used?")
	}
	if prob.Type != probs.TLSProblem {
		t.Errorf("Wrong problem type: got %s, expected type %s",
			prob, probs.TLSProblem)
	}
}

func TestDNSError(t *testing.T) {
	chall := tlsalpnChallenge()
	hs := brokenTLSSrv()

	va, _ := setup(hs, 0, "", nil)

	_, prob := va.validateTLSALPN01(ctx, dnsi("always.invalid"), chall)
	if prob == nil {
		t.Fatalf("TLS validation should have failed: what IP was used?")
	}
	if prob.Type != probs.DNSProblem {
		t.Errorf("Wrong problem type: got %s, expected type %s",
			prob, probs.DNSProblem)
	}
}

func TestCertNames(t *testing.T) {
	// We duplicate names inside the SAN set
	names := []string{
		"hello.world", "goodbye.world",
		"hello.world", "goodbye.world",
		"bonjour.le.monde", "au.revoir.le.monde",
		"bonjour.le.monde", "au.revoir.le.monde",
	}
	// We expect only unique names, in sorted order.
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
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &TheKey.PublicKey, &TheKey)
	test.AssertNotError(t, err, "Error creating certificate")

	cert, err := x509.ParseCertificate(certBytes)
	test.AssertNotError(t, err, "Error parsing certificate")

	actual := certNames(cert)
	test.AssertDeepEquals(t, actual, expected)
}

func TestTLSALPN01Success(t *testing.T) {
	chall := tlsalpnChallenge()
	hs, err := tlsalpn01Srv(t, chall, IdPeAcmeIdentifier, 0, "localhost")
	test.AssertNotError(t, err, "Error creating test server")

	va, _ := setup(hs, 0, "", nil)

	_, prob := va.validateChallenge(ctx, dnsi("localhost"), chall)
	if prob != nil {
		t.Errorf("Validation failed: %v", prob)
	}
	test.AssertMetricWithLabelsEquals(
		t, va.metrics.tlsALPNOIDCounter, prometheus.Labels{"oid": IdPeAcmeIdentifier.String()}, 1)

	hs.Close()
}

func TestTLSALPN01ObsoleteFailure(t *testing.T) {
	// NOTE: unfortunately another document claimed the OID we were using in
	// draft-ietf-acme-tls-alpn-01 for their own extension and IANA chose to
	// assign it early. Because of this we had to increment the
	// id-pe-acmeIdentifier OID. We supported this obsolete OID for a long time,
	// but no longer do so.
	// As defined in https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-01#section-5.1
	// id-pe OID + 30 (acmeIdentifier) + 1 (v1)
	IdPeAcmeIdentifierV1Obsolete := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 30, 1}

	chall := tlsalpnChallenge()
	hs, err := tlsalpn01Srv(t, chall, IdPeAcmeIdentifierV1Obsolete, 0, "localhost")
	test.AssertNotError(t, err, "Error creating test server")

	va, _ := setup(hs, 0, "", nil)

	_, prob := va.validateChallenge(ctx, dnsi("localhost"), chall)
	test.AssertNotNil(t, prob, "expected validation to fail")
}

func TestValidateTLSALPN01BadChallenge(t *testing.T) {
	chall := tlsalpnChallenge()
	chall2 := chall
	setChallengeToken(&chall2, "bad token")

	hs, err := tlsalpn01Srv(t, chall2, IdPeAcmeIdentifier, 0, "localhost")
	test.AssertNotError(t, err, "Error creating test server")

	va, _ := setup(hs, 0, "", nil)

	_, prob := va.validateTLSALPN01(ctx, dnsi("localhost"), chall)

	if prob == nil {
		t.Fatalf("TLS ALPN validation should have failed.")
	}
	test.AssertEquals(t, prob.Type, probs.UnauthorizedProblem)

	expectedDigest := sha256.Sum256([]byte(chall.ProvidedKeyAuthorization))
	badDigest := sha256.Sum256([]byte(chall2.ProvidedKeyAuthorization))

	test.AssertEquals(t, prob.Detail, fmt.Sprintf(
		"Incorrect validation certificate for %s challenge. "+
			"Expected acmeValidationV1 extension value %s for this challenge but got %s",
		core.ChallengeTypeTLSALPN01,
		hex.EncodeToString(expectedDigest[:]),
		hex.EncodeToString(badDigest[:])))
}

func TestValidateTLSALPN01BrokenSrv(t *testing.T) {
	chall := tlsalpnChallenge()
	hs := brokenTLSSrv()

	va, _ := setup(hs, 0, "", nil)

	_, prob := va.validateTLSALPN01(ctx, dnsi("localhost"), chall)
	if prob == nil {
		t.Fatalf("TLS ALPN validation should have failed.")
	}
	test.AssertEquals(t, prob.Type, probs.TLSProblem)
}

func TestValidateTLSALPN01UnawareSrv(t *testing.T) {
	chall := tlsalpnChallenge()
	hs := tlssniSrvWithNames(t, chall, "localhost")

	va, _ := setup(hs, 0, "", nil)

	_, prob := va.validateTLSALPN01(ctx, dnsi("localhost"), chall)
	if prob == nil {
		t.Fatalf("TLS ALPN validation should have failed.")
	}
	// In go1.16 it makes the connection but shouldn't be able to complete it;
	// in go1.17 the stdlib refuses to handshake when there is no overlap in
	// negotiated TLS application protocols.
	go116ok := prob.Type == probs.UnauthorizedProblem
	go117ok := prob.Type == probs.TLSProblem
	test.Assert(t, go116ok != go117ok, "Only one of go1.16 or go1.17 should pass")
}

// TestValidateTLSALPN01BadUTFSrv tests that validating TLS-ALPN-01 against
// a host that returns a certificate with a SAN/CN that contains invalid UTF-8
// will result in a problem with the invalid UTF-8.
func TestValidateTLSALPN01BadUTFSrv(t *testing.T) {
	chall := tlsalpnChallenge()
	_, err := tlsalpn01Srv(t, chall, IdPeAcmeIdentifier, 0, "localhost", "\xf0\x28\x8c\xbc")
	test.AssertContains(t, err.Error(), "cannot be encoded as an IA5String")
}

// TestValidateTLSALPN01MalformedExtnValue tests that validating TLS-ALPN-01
// against a host that returns a certificate that contains an ASN.1 DER
// acmeValidation extension value that does not parse or is the wrong length
// will result in an Unauthorized problem
func TestValidateTLSALPN01MalformedExtnValue(t *testing.T) {
	chall := tlsalpnChallenge()

	names := []string{"localhost"}
	template := tlsCertTemplate(names)
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &TheKey.PublicKey, &TheKey)
	cert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  &TheKey,
	}

	wrongTypeDER, _ := asn1.Marshal("a string")
	wrongLengthDER, _ := asn1.Marshal(make([]byte, 31))
	badExtensions := []pkix.Extension{
		{
			Id:       IdPeAcmeIdentifier,
			Critical: true,
			Value:    wrongTypeDER,
		},
		{
			Id:       IdPeAcmeIdentifier,
			Critical: true,
			Value:    wrongLengthDER,
		},
	}

	malformedMsg := fmt.Sprintf("Incorrect validation certificate for %s challenge. "+
		"Malformed acmeValidationV1 extension value", core.ChallengeTypeTLSALPN01)

	for _, badExt := range badExtensions {
		template.ExtraExtensions = []pkix.Extension{badExt}
		certBytes, _ = x509.CreateCertificate(rand.Reader, template, template, &TheKey.PublicKey, &TheKey)
		acmeCert := &tls.Certificate{
			Certificate: [][]byte{certBytes},
			PrivateKey:  &TheKey,
		}

		hs := tlsalpn01SrvWithCert(t, chall, IdPeAcmeIdentifier, names, cert, acmeCert, 0)
		va, _ := setup(hs, 0, "", nil)

		_, prob := va.validateTLSALPN01(ctx, dnsi("localhost"), chall)
		hs.Close()

		if prob == nil {
			t.Errorf("TLS ALPN validation should have failed for acmeValidation extension %+v.",
				badExt)
			continue
		}
		test.AssertEquals(t, prob.Type, probs.UnauthorizedProblem)
		test.AssertEquals(t, prob.Detail, malformedMsg)
	}

}

func TestTLSALPN01TLSVersion(t *testing.T) {
	for _, tc := range []struct {
		version     uint16
		expectError bool
	}{
		{
			version:     tls.VersionTLS11,
			expectError: true,
		},
		{
			version:     tls.VersionTLS12,
			expectError: false,
		},
		{
			version:     tls.VersionTLS13,
			expectError: false,
		},
	} {
		chall := tlsalpnChallenge()

		// Create a server that only negotiates the given TLS version
		hs, err := tlsalpn01Srv(t, chall, IdPeAcmeIdentifier, tc.version, "localhost")
		test.AssertNotError(t, err, "Error creating test server")

		va, _ := setup(hs, 0, "", nil)

		_, prob := va.validateChallenge(ctx, dnsi("localhost"), chall)
		if !tc.expectError {
			if prob != nil {
				t.Errorf("expected success, got: %v", prob)
			}
			// The correct TLS-ALPN-01 OID counter should have been incremented
			test.AssertMetricWithLabelsEquals(
				t, va.metrics.tlsALPNOIDCounter, prometheus.Labels{"oid": IdPeAcmeIdentifier.String()}, 1)
		} else {
			test.AssertNotNil(t, prob, "expected validation error")
			test.AssertMetricWithLabelsEquals(
				t, va.metrics.tlsALPNOIDCounter, prometheus.Labels{"oid": IdPeAcmeIdentifier.String()}, 0)
		}

		hs.Close()
	}
}
