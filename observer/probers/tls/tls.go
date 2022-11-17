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
	"net/http"
	"time"
)

const (
	Success = iota
	UnexpectedRoot
	UnexpectedResponse
	UnexpectedRootAndResponse
	UnknownOCSPCheck
	FailedOCSPCheck
	FailedTLSConnection
	UnknownFailure
)

// TLSProbe is the exported `Prober` object for monitors configured to perform
// TLS protocols.
type TLSProbe struct {
	url        string
	root       string
	response   string
	certExpiry *prometheus.GaugeVec
	outcome    *prometheus.GaugeVec
}

// Name returns a string that uniquely identifies the monitor.
func (p TLSProbe) Name() string {
	return fmt.Sprintf("%s-expecting-%s-%s", p.url, p.response, p.root)
}

// Kind returns a name that uniquely identifies the `Kind` of `Prober`.
func (p TLSProbe) Kind() string {
	return "TLS"
}

func isOCSPRevoked(outcome int, cert, issuer *x509.Certificate) (int, bool) {
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		outcome = FailedOCSPCheck
		return outcome, false
	}

	url := fmt.Sprintf("%s/%s", cert.OCSPServer[0], base64.StdEncoding.EncodeToString(req))
	res, err := http.Get(url)
	if err != nil {
		outcome = FailedOCSPCheck
		return outcome, false
	}

	output, err := io.ReadAll(res.Body)
	if err != nil {
		outcome = FailedOCSPCheck
		return outcome, false
	}

	ocspRes, err := ocsp.ParseResponseForCert(output, cert, issuer)
	if err != nil {
		outcome = FailedOCSPCheck
		return outcome, false
	}

	if ocspRes.Status == ocsp.Revoked {
		return outcome, true
	} else {
		if ocspRes.Status == ocsp.Unknown {
			outcome = UnknownOCSPCheck
		}
		return outcome, false
	}
}

func (p TLSProbe) getExpiredCertInfo(outcome int) (int, string, string, time.Duration) {
	conf := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", p.url+":443", conf)
	if err != nil {
		outcome = FailedTLSConnection
		return outcome, "", "", 0
	}
	peers := conn.ConnectionState().PeerCertificates
	expiry_date := peers[0].NotAfter
	root := peers[len(peers)-1].Issuer
	return outcome, root.CommonName, root.Organization[0], time.Since(expiry_date)
}

func updateOutcome(outcome int, is_expected_root, is_expected_response bool) int {
	if !is_expected_root && !is_expected_response {
		outcome = UnexpectedRootAndResponse
	} else if !is_expected_root {
		outcome = UnexpectedRoot
	} else if !is_expected_response {
		outcome = UnexpectedResponse
	}
	return outcome
}

// Probe performs the configured TLS protocol. Return true if both root AND
// response are the expected values, otherwise false. Export time to cert expiry
// and outcome as a Prometheus metric.
func (p TLSProbe) Probe(timeout time.Duration) (bool, time.Duration) {
	is_expected_root, is_expected_response := false, false
	root_cn, root_o := "", ""
	var time_to_expiry time.Duration
	var time_since_expiry time.Duration
	outcome := Success

	start := time.Now()
	conn, err := tls.Dial("tcp", p.url+":443", &tls.Config{})
	if err != nil {
		// Check if the TLS connection error is due to an expired certificate.
		certInvalidErr := x509.CertificateInvalidError{}
		if errors.As(err, &certInvalidErr) && certInvalidErr.Reason == x509.Expired {
			if p.response == "expired" {
				is_expected_response = true
			}
			// Certificate shouldn't be expired, but check root and get expiry
			// time anyways.
			outcome, root_cn, root_o, time_since_expiry = p.getExpiredCertInfo(outcome)
		} else {
			outcome = FailedTLSConnection
		}
	} else {
		defer conn.Close()
		chains := conn.ConnectionState().VerifiedChains
		end_cert, issuer, root_cert := chains[0][0], chains[0][1], chains[0][len(chains[0])-1].Issuer
		time_to_expiry = time.Until(end_cert.NotAfter)
		root_cn, root_o = root_cert.CommonName, root_cert.Organization[0]

		// Check OCSP to see if the certificate is valid or revoked. If OCSP
		// returns unknown, assume it's not revoked.
		var is_revoked bool
		outcome, is_revoked = isOCSPRevoked(outcome, end_cert, issuer)
		if (p.response == "revoked" && is_revoked) || (p.response == "valid" && !is_revoked) {
			is_expected_response = true
		}
	}

	// Check if the root is the one we expect.
	if p.root == fmt.Sprintf("/O=%s/CN=%s", root_o, root_cn) {
		is_expected_root = true
	}

	// Export time to (or since) expiration to Prometheus.
	if time_since_expiry != start.Sub(start) {
		p.certExpiry.WithLabelValues(p.url).Set(-time_since_expiry.Seconds())
	} else {
		p.certExpiry.WithLabelValues(p.url).Set(time_to_expiry.Seconds())
	}

	// Export outcome to Prometheus
	if outcome == Success {
		outcome = updateOutcome(outcome, is_expected_root, is_expected_response)
	}
	p.certExpiry.WithLabelValues(p.url).Set(float64(outcome))

	return is_expected_root && is_expected_response, time.Since(start)
}
