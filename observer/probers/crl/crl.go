package probers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"slices"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/letsencrypt/boulder/crl/idp"
	"github.com/letsencrypt/boulder/observer/obsdialer"
)

// CRLProbe is the exported 'Prober' object for monitors configured to
// monitor CRL availability & characteristics.
type CRLProbe struct {
	url         string
	partitioned bool
	cNextUpdate *prometheus.GaugeVec
	cThisUpdate *prometheus.GaugeVec
	cCertCount  *prometheus.GaugeVec
}

// Name returns a string that uniquely identifies the monitor.
func (p CRLProbe) Name() string {
	return p.url
}

// Kind returns a name that uniquely identifies the `Kind` of `Prober`.
func (p CRLProbe) Kind() string {
	return "CRL"
}

// Probe requests the configured CRL and publishes metrics about it if found.
func (p CRLProbe) Probe(ctx context.Context) bool {
	client := http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     obsdialer.Dialer.DialContext,
	}}
	req, err := http.NewRequestWithContext(ctx, "GET", p.url, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return false
	}

	// Partitioned CRLs MUST contain an issuingDistributionPoint extension, which
	// MUST contain the URL from which they were fetched, to prevent substitution
	// attacks.
	if p.partitioned {
		idps, err := idp.GetIDPURIs(crl.Extensions)
		if err != nil {
			return false
		}
		if !slices.Contains(idps, p.url) {
			return false
		}
	}

	// Report metrics for this CRL
	p.cThisUpdate.WithLabelValues(p.url).Set(float64(crl.ThisUpdate.Unix()))
	p.cNextUpdate.WithLabelValues(p.url).Set(float64(crl.NextUpdate.Unix()))
	p.cCertCount.WithLabelValues(p.url).Set(float64(len(crl.RevokedCertificateEntries)))

	return true
}
