package probers

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
	"io"
	"log"
	"net/http"
	"time"
)

// TLSProbe is the exported 'Prober' object for monitors configured to
// perform TLS protocols.
type TLSProbe struct {
	url        string
	root       string
	response   string
	certExpiry *prometheus.GaugeVec
}

// Name returns a string that uniquely identifies the monitor.
func (p TLSProbe) Name() string {
	return fmt.Sprintf("%s-%s", p.url, p.root)
}

// Kind returns a name that uniquely identifies the `Kind` of `Prober`.
func (p TLSProbe) Kind() string {
	return "TLS"
}

func isOCSPRevoked(cert, issuer *x509.Certificate) bool {
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		log.Fatalf("%s", err)
	}

	url := fmt.Sprintf("%s/%s", cert.OCSPServer[0], base64.StdEncoding.EncodeToString(req))
	res, err := http.Get(url)
	if err != nil {
		log.Fatalf("%s", err)
	}

	output, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("%s", err)
	}

	ocspRes, err := ocsp.ParseResponseForCert(output, cert, issuer)
	if err != nil {
		panic(err)
	}
	if ocspRes.Status != ocsp.Revoked {
		return false
	}
	return true
}

func getExpiredRootInfo() (bool, time.Duration) {
	return true, time.Minute
}

// Probe performs the configured TLS protocol.
// Return true if both root AND response are the expected values, otherwise false
// Export time to cert expiry as Prometheus metric
func (p TLSProbe) Probe(timeout time.Duration) (bool, time.Duration) {
	expected_root, expected_response := false, false

	conf := &tls.Config{}
	start := time.Now()
	conn, err := tls.Dial("tcp", p.url+":443", conf)
	if err != nil {
		certInvalidErr := x509.CertificateInvalidError{}
		if errors.As(err, &certInvalidErr) && certInvalidErr.Reason == x509.Expired {
			if p.response == "expired" {
				expected_response = true
			} //need a way to still verify root and get time since expiry
		}
	} else {
		defer conn.Close()
		chains := conn.ConnectionState().VerifiedChains
		for _, chain := range chains {
			root_cert := chain[len(chain)-1]
			if p.root == fmt.Sprintf("/O=%s/CN=%s", root_cert.Issuer.Organization[0], root_cert.Issuer.CommonName) {
				expected_root = true
				break
			}
		}
		end_cert, issuer := chains[0][0], chains[0][1]
		time_to_expiry := time.Until(end_cert.NotAfter)

		is_revoked := isOCSPRevoked(end_cert, issuer)
		if (p.response == "revoked" && is_revoked) || (p.response == "valid" && !is_revoked) {
			expected_response = true
		}

		p.certExpiry.WithLabelValues(p.url).Set(time_to_expiry.Seconds())
	}

	return expected_root && expected_response, time.Since(start)
}
