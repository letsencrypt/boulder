package probers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/letsencrypt/boulder/test"
)

// TestAIAProbe_Probe tests the Probe method of AIAProbe
func TestAIAProbe_Probe(t *testing.T) {
	// Create a test CA certificate
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "generating private key")

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	test.AssertNotError(t, err, "creating certificate")

	// Create a test non-CA certificate
	nonCATemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "Not a CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	nonCACertDER, err := x509.CreateCertificate(rand.Reader, &nonCATemplate, &nonCATemplate, &privateKey.PublicKey, privateKey)
	test.AssertNotError(t, err, "creating non-CA certificate")

	// Test with valid CA certificate and correct content-type
	t.Run("valid CA certificate", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/pkix-cert")
			w.Write(certDER)
		}))
		defer ts.Close()

		conf := AIAConf{URL: ts.URL, ExpectCommonName: "Test CA"}
		prober, err := conf.MakeProber(conf.Instrument())
		test.AssertNotError(t, err, "making prober")

		err = prober.Probe(t.Context())
		if err != nil {
			t.Errorf("Probe() = %q, but want success", err)
		}

		// Check metric values are set to right values
		aiaProber, ok := prober.(AIAProbe)
		test.Assert(t, ok, "prober should be AIAProbe")
		test.AssertMetricWithLabelsEquals(t, aiaProber.cNotBefore, prometheus.Labels{"url": ts.URL}, float64(template.NotBefore.Unix()))
		test.AssertMetricWithLabelsEquals(t, aiaProber.cNotAfter, prometheus.Labels{"url": ts.URL}, float64(template.NotAfter.Unix()))
	})

	// Test with valid CA certificate but wrong CommonName
	t.Run("valid CA certificate with non-matching CommonName", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/pkix-cert")
			w.Write(certDER)
		}))
		defer ts.Close()

		conf := AIAConf{URL: ts.URL, ExpectCommonName: "Wrong CA"}
		prober, err := conf.MakeProber(conf.Instrument())
		test.AssertNotError(t, err, "making prober")

		err = prober.Probe(t.Context())
		if err == nil || !strings.Contains(err.Error(), "certificate has CN \"Test CA\" but want \"Wrong CA\"") {
			t.Errorf("Probe() = %q, but want wrong CN error", err)
		}
	})

	// Test with non-CA certificate
	t.Run("non-CA certificate", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/pkix-cert")
			w.Write(nonCACertDER)
		}))
		defer ts.Close()

		conf := AIAConf{URL: ts.URL, ExpectCommonName: "Not a CA"}
		prober, err := conf.MakeProber(conf.Instrument())
		test.AssertNotError(t, err, "making prober")

		err = prober.Probe(t.Context())
		if err == nil || !strings.Contains(err.Error(), "certificate is not a CA certificate") {
			t.Errorf("Probe() = %q, but want not a CA error", err)
		}
	})

	// Test with wrong content-type
	t.Run("wrong content-type", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write(certDER)
		}))
		defer ts.Close()

		conf := AIAConf{URL: ts.URL, ExpectCommonName: "Test CA"}
		prober, err := conf.MakeProber(conf.Instrument())
		test.AssertNotError(t, err, "making prober")

		err = prober.Probe(t.Context())
		if err == nil || !strings.Contains(err.Error(), "but want application/pkix-cert") {
			t.Errorf("Probe() = %q, but want Content-Type error", err)
		}
	})

	// Test with invalid certificate data
	t.Run("invalid certificate", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/pkix-cert")
			w.Write([]byte("not a certificate"))
		}))
		defer ts.Close()

		conf := AIAConf{URL: ts.URL, ExpectCommonName: "Test CA"}
		prober, err := conf.MakeProber(conf.Instrument())
		test.AssertNotError(t, err, "making prober")

		err = prober.Probe(t.Context())
		if err == nil || !strings.Contains(err.Error(), "x509: malformed certificate") {
			t.Errorf("Probe() = %q, but want parse error", err)
		}
	})

	// Test with unreachable server
	t.Run("unreachable server", func(t *testing.T) {
		conf := AIAConf{URL: "http://127.0.0.1:1", ExpectCommonName: "Test CA"}
		prober, err := conf.MakeProber(conf.Instrument())
		test.AssertNotError(t, err, "making prober")

		err = prober.Probe(t.Context())
		if err == nil || !strings.Contains(err.Error(), "connection refused") {
			t.Errorf("Probe() = %q, but want unreachable server error", err)
		}
	})
}
