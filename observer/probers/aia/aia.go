package probers

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// AIAProbe is the exported 'Prober' object for monitors configured to
// monitor AIA certificate availability & characteristics.
type AIAProbe struct {
	url              string
	expectCommonName string
	cNotBefore       *prometheus.GaugeVec
	cNotAfter        *prometheus.GaugeVec
}

// Name returns a string that uniquely identifies the monitor.
func (p AIAProbe) Name() string {
	return p.url
}

// Kind returns a name that uniquely identifies the `Kind` of `Prober`.
func (p AIAProbe) Kind() string {
	return "AIA"
}

// Probe requests the configured AIA certificate and publishes metrics about it if found.
func (p AIAProbe) Probe(timeout time.Duration) (bool, time.Duration) {
	start := time.Now()

	// Create a client with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", p.url, nil)
	if err != nil {
		return false, time.Since(start)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, time.Since(start)
	}
	defer resp.Body.Close()

	// Check Content-Type header
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/pkix-cert" {
		return false, time.Since(start)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, time.Since(start)
	}
	dur := time.Since(start)

	// Parse the DER-encoded certificate
	cert, err := x509.ParseCertificate(body)
	if err != nil {
		return false, dur
	}

	// Check if the certificate is a CA certificate
	if !cert.IsCA {
		return false, dur
	}

	// Check if the CommonName matches the expected value (if provided)
	if p.expectCommonName != "" && cert.Subject.CommonName != p.expectCommonName {
		return false, dur
	}

	// Report metrics for this certificate
	p.cNotBefore.WithLabelValues(p.url).Set(float64(cert.NotBefore.Unix()))
	p.cNotAfter.WithLabelValues(p.url).Set(float64(cert.NotAfter.Unix()))

	return true, dur
}
