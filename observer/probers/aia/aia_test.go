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

		success, dur := prober.Probe(5 * time.Second)
		test.Assert(t, success, "probe should succeed")
		test.Assert(t, dur > 0, "duration should be positive")
	})

	// Test with valid CA certificate and correct CommonName
	t.Run("valid CA certificate with matching CommonName", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/pkix-cert")
			w.Write(certDER)
		}))
		defer ts.Close()

		conf := AIAConf{URL: ts.URL, ExpectCommonName: "Test CA"}
		colls := conf.Instrument()
		prober, err := conf.MakeProber(colls)
		test.AssertNotError(t, err, "making prober")

		success, dur := prober.Probe(5 * time.Second)
		test.Assert(t, success, "probe should succeed with matching CommonName")
		test.Assert(t, dur > 0, "duration should be positive")
	})

	// Test with valid CA certificate but wrong CommonName
	t.Run("valid CA certificate with non-matching CommonName", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/pkix-cert")
			w.Write(certDER)
		}))
		defer ts.Close()

		conf := AIAConf{URL: ts.URL, ExpectCommonName: "Wrong CA"}
		colls := conf.Instrument()
		prober, err := conf.MakeProber(colls)
		test.AssertNotError(t, err, "making prober")

		success, _ := prober.Probe(5 * time.Second)
		test.Assert(t, !success, "probe should fail with non-matching CommonName")
	})

	// Create a non-CA certificate for testing
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

	// Test with non-CA certificate
	t.Run("non-CA certificate", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/pkix-cert")
			w.Write(nonCACertDER)
		}))
		defer ts.Close()

		conf := AIAConf{URL: ts.URL, ExpectCommonName: "Not a CA"}
		colls := conf.Instrument()
		prober, err := conf.MakeProber(colls)
		test.AssertNotError(t, err, "making prober")

		success, _ := prober.Probe(5 * time.Second)
		test.Assert(t, !success, "probe should fail with non-CA certificate")
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

		success, _ := prober.Probe(5 * time.Second)
		test.Assert(t, !success, "probe should fail with wrong content-type")
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

		success, _ := prober.Probe(5 * time.Second)
		test.Assert(t, !success, "probe should fail with invalid certificate")
	})

	// Test with unreachable server
	t.Run("unreachable server", func(t *testing.T) {
		conf := AIAConf{URL: "http://127.0.0.1:1", ExpectCommonName: "Test CA"}
		prober, err := conf.MakeProber(conf.Instrument())
		test.AssertNotError(t, err, "making prober")

		success, _ := prober.Probe(1 * time.Second)
		test.Assert(t, !success, "probe should fail with unreachable server")
	})
}

// TestAIAProbe_Metrics tests that metrics are correctly set
func TestAIAProbe_Metrics(t *testing.T) {
	// Create a test CA certificate
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "generating private key")

	notBefore := time.Now().Add(-24 * time.Hour)
	notAfter := time.Now().Add(365 * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "Test CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	test.AssertNotError(t, err, "creating certificate")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-cert")
		w.Write(certDER)
	}))
	defer ts.Close()

	conf := AIAConf{URL: ts.URL, ExpectCommonName: "Test CA"}
	colls := conf.Instrument()

	// Register metrics with a test registry
	testReg := prometheus.NewRegistry()
	for _, coll := range colls {
		testReg.MustRegister(coll)
	}

	prober, err := conf.MakeProber(colls)
	test.AssertNotError(t, err, "making prober")

	success, _ := prober.Probe(5 * time.Second)
	test.Assert(t, success, "probe should succeed")

	// Check that metrics were gathered
	metricFamilies, err := testReg.Gather()
	test.AssertNotError(t, err, "gathering metrics")

	// Verify we have the expected metrics
	test.AssertEquals(t, len(metricFamilies), 2)
}
