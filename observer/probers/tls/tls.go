package probers

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
)

type reason int

type badOutcomeError struct {
	reason reason
}

const (
	_ reason = iota
	unexpectedRoot
	unexpectedResponse
	unexpectedRootAndResponse
	oCSPUnknown
	issuerVerifyFailed
	internalError
	numOutcomes
)

func (e badOutcomeError) Error() string {
	switch e.reason {
	case unexpectedRoot:
		return "unexpectedRoot"
	case unexpectedResponse:
		return "unexpectedResponse"
	case unexpectedRootAndResponse:
		return "unexpectedRootAndResponse"
	case oCSPUnknown:
		return "oCSPUnknown"
	case issuerVerifyFailed:
		return "issuerVerifyFailed"
	case internalError:
		return "internalError"
	}
	return ""
}

func getListOutcomes() []string {
	outcomes := make([]string, numOutcomes)
	for i := 1; i < int(numOutcomes); i++ {
		e := badOutcomeError{reason(i)}
		outcomes[i] = e.Error()
	}
	return outcomes
}

var (
	errOCSPUnknown        = errors.New("OCSP status unknown")
	errIssuerVerifyFailed = errors.New("issuer verify failed for expired certificate")
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

func isOCSPRevoked(cert, issuer *x509.Certificate) (bool, error) {
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return false, err
	}

	url := fmt.Sprintf("%s/%s", cert.OCSPServer[0], base64.StdEncoding.EncodeToString(req))
	res, err := http.Get(url)
	if err != nil {
		return false, err
	}

	output, err := io.ReadAll(res.Body)
	if err != nil {
		return false, err
	}

	ocspRes, err := ocsp.ParseResponseForCert(output, cert, issuer)
	if err != nil {
		return false, err
	}

	switch ocspRes.Status {
	case ocsp.Revoked:
		return true, nil
	case ocsp.Good:
		return false, nil
	default:
		return false, errOCSPUnknown
	}
}

func (p TLSProbe) getExpiredCertInfo() (string, string, time.Duration, error) {
	conf := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", p.url+":443", conf)
	if err != nil {
		return "", "", 0, err
	}
	peers := conn.ConnectionState().PeerCertificates
	expiry_date := peers[0].NotAfter

	for i := 0; i < len(peers)-1; i++ {
		cert_issuer, issuer_subject := peers[i].Issuer, peers[i+1].Subject
		if (cert_issuer.CommonName != issuer_subject.CommonName) || (cert_issuer.Organization[0] != issuer_subject.Organization[0]) {
			err = errIssuerVerifyFailed
		}
	}

	root := peers[len(peers)-1].Issuer
	return root.CommonName, root.Organization[0], time.Since(expiry_date), err
}

func (r reason) update(is_expected_root, is_expected_response bool) reason {
	if !is_expected_root && !is_expected_response {
		r = unexpectedRootAndResponse
	} else if !is_expected_root {
		r = unexpectedRoot
	} else if !is_expected_response {
		r = unexpectedResponse
	}
	return r
}

// Probe performs the configured TLS protocol. Return true if both root AND
// response are the expected values, otherwise false. Export time to cert expiry
// and outcome as a Prometheus metric.
func (p TLSProbe) Probe(timeout time.Duration) (bool, time.Duration) {
	is_expected_root, is_expected_response := false, false
	root_cn, root_o := "", ""
	var time_to_expiry time.Duration
	var time_since_expiry time.Duration
	var badOutcome reason

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
			root_cn, root_o, time_since_expiry, err = p.getExpiredCertInfo()
			if err != nil {
				if errors.Is(err, errIssuerVerifyFailed) {
					badOutcome = issuerVerifyFailed
				} else {
					badOutcome = internalError
				}
			}
		} else {
			badOutcome = internalError
		}
	} else {
		defer conn.Close()
		chains := conn.ConnectionState().VerifiedChains
		leaf, issuer, root_cert := chains[0][0], chains[0][1], chains[0][len(chains[0])-1].Issuer
		time_to_expiry = time.Until(leaf.NotAfter)
		root_cn, root_o = root_cert.CommonName, root_cert.Organization[0]

		// Check OCSP to see if the certificate is valid, revoked or unknown.
		is_revoked, err := isOCSPRevoked(leaf, issuer)
		if err != nil {
			if errors.Is(err, errOCSPUnknown) {
				badOutcome = oCSPUnknown
			} else {
				badOutcome = internalError
			}
		} else if (p.response == "revoked" && is_revoked) || (p.response == "valid" && !is_revoked) {
			is_expected_response = true
		}
	}

	// Check if the root is the one we expect.
	if p.root == fmt.Sprintf("/O=%s/CN=%s", root_o, root_cn) {
		is_expected_root = true
	}

	// Export time to (or since) expiration to Prometheus.
	if time_since_expiry != 0 {
		p.certExpiry.WithLabelValues(p.url).Set(-time_since_expiry.Seconds())
	} else {
		p.certExpiry.WithLabelValues(p.url).Set(time_to_expiry.Seconds())
	}

	if badOutcome == 0 {
		badOutcome = badOutcome.update(is_expected_root, is_expected_response)
	}

	// Export outcome to Prometheus with outcome label.
	p.certExpiry.WithLabelValues(p.url, badOutcomeError{badOutcome}.Error()).Set(float64(badOutcome))

	return is_expected_root && is_expected_response, time.Since(start)
}
