package probers

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
)

type reason int

const (
	none reason = iota
	internalError
	issuerVerifyFailed
	ocspUnknown
	ocspError
)

var reasonToString = map[reason]string{
	none:               "nil",
	internalError:      "internalError",
	issuerVerifyFailed: "issuerVerifyFailed",
	ocspUnknown:        "ocspUnknown",
	ocspError:          "ocspError",
}

func getReasons() []string {
	var allReasons []string
	for _, v := range reasonToString {
		allReasons = append(allReasons, v)
	}
	return allReasons
}

// TLSProbe is the exported `Prober` object for monitors configured to perform
// TLS protocols.
type TLSProbe struct {
	hostname string
	rootOrg  string
	rootCN   string
	response string
	notAfter *prometheus.GaugeVec
	reason   *prometheus.CounterVec
}

// Name returns a string that uniquely identifies the monitor.
func (p TLSProbe) Name() string {
	return p.hostname
}

// Kind returns a name that uniquely identifies the `Kind` of `Prober`.
func (p TLSProbe) Kind() string {
	return "TLS"
}

// Get OCSP status (good, revoked or unknown) of certificate
func checkOCSP(cert, issuer *x509.Certificate, want int) (bool, error) {
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

	return ocspRes.Status == want, nil
}

// Export expiration timestamp and reason to Prometheus.
func (p TLSProbe) exportMetrics(notAfter time.Time, reason reason) {
	p.notAfter.WithLabelValues(p.hostname).Set(float64(notAfter.Unix()))
	p.reason.WithLabelValues(p.hostname, reasonToString[reason]).Inc()
}

func (p TLSProbe) probeExpired(timeout time.Duration) bool {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", p.hostname+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		p.exportMetrics(time.Time{}, internalError)
		return false
	}

	defer conn.Close()
	peers := conn.ConnectionState().PeerCertificates
	for i := 0; i < len(peers)-1; i++ {
		certIssuer, issuerSubject := peers[i].Issuer, peers[i+1].Subject
		if (certIssuer.CommonName != issuerSubject.CommonName) || (certIssuer.Organization[0] != issuerSubject.Organization[0]) {
			p.exportMetrics(peers[0].NotAfter, issuerVerifyFailed)
			return false
		}
	}

	p.exportMetrics(peers[0].NotAfter, none)
	if time.Until(peers[0].NotAfter) > 0 {
		return false
	}

	root := peers[len(peers)-1].Issuer
	return root.Organization[0] == p.rootOrg && root.CommonName == p.rootCN
}

func (p TLSProbe) probeUnexpired(timeout time.Duration) bool {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", p.hostname+":443", &tls.Config{})
	if err != nil {
		p.exportMetrics(time.Time{}, internalError)
		return false
	}

	defer conn.Close()
	peers := conn.ConnectionState().PeerCertificates
	root := peers[len(peers)-1].Issuer
	if root.Organization[0] != p.rootOrg || root.CommonName != p.rootCN {
		p.exportMetrics(peers[0].NotAfter, none)
		return false
	}

	var ocspStatus bool
	switch p.response {
	case "valid":
		ocspStatus, err = checkOCSP(peers[0], peers[1], ocsp.Good)
	case "revoked":
		ocspStatus, err = checkOCSP(peers[0], peers[1], ocsp.Revoked)
	}
	if err != nil {
		p.exportMetrics(peers[0].NotAfter, ocspError)
		return false
	}

	p.exportMetrics(peers[0].NotAfter, none)
	return ocspStatus
}

// Probe performs the configured TLS probe. Return true if the root has the
// expected Subject, and the end entity certificate has the correct expiration status
// (either expired or unexpired, depending on what is configured). Exports metrics
// for the NotAfter timestamp of the end entity certificate and its revocation
// reason (from OCSP).
func (p TLSProbe) Probe(timeout time.Duration) (bool, time.Duration) {
	start := time.Now()
	var success bool
	if p.response == "expired" {
		success = p.probeExpired(timeout)
	} else {
		success = p.probeUnexpired(timeout)
	}

	return success, time.Since(start)
}
