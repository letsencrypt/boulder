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

func (p TLSProbe) getExpiredCertInfo() (string, string, time.Duration) {
	conf := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", p.url+":443", conf)
	if err != nil {
		return "", "", 0
	}
	peers := conn.ConnectionState().PeerCertificates
	expiry_date := peers[0].NotAfter
	root := peers[len(peers)-1].Issuer
	return root.CommonName, root.Organization[0], time.Since(expiry_date)
}

// Probe performs the configured TLS protocol.
// Return true if both root AND response are the expected values, otherwise false
// Export time to cert expiry as Prometheus metric
func (p TLSProbe) Probe(timeout time.Duration) (bool, time.Duration) {
	is_expected_root, is_expected_response := false, false
	root_cn, root_o := "", ""
	var time_to_expiry time.Duration
	var time_since_expiry time.Duration

	conf := &tls.Config{}
	start := time.Now()
	conn, err := tls.Dial("tcp", p.url+":443", conf)
	if err != nil {
		// check expired or return unknown
		certInvalidErr := x509.CertificateInvalidError{}
		if errors.As(err, &certInvalidErr) && certInvalidErr.Reason == x509.Expired {
			if p.response == "expired" {
				is_expected_response = true
			}
			// incorrect response, but check the rest anyways
			root_cn, root_o, time_since_expiry = p.getExpiredCertInfo()
		}
		// return unknown
	} else {
		// check valid, revoked, or unknown
		defer conn.Close()
		chains := conn.ConnectionState().VerifiedChains
		end_cert, issuer, root_cert := chains[0][0], chains[0][1], chains[0][len(chains[0])-1].Issuer
		time_to_expiry = time.Until(end_cert.NotAfter)
		root_cn, root_o = root_cert.CommonName, root_cert.Organization[0]

		is_revoked := isOCSPRevoked(end_cert, issuer)
		if (p.response == "revoked" && is_revoked) || (p.response == "valid" && !is_revoked) {
			is_expected_response = true
		}
	}

	// check root
	if p.root == fmt.Sprintf("/O=%s/CN=%s", root_o, root_cn) {
		is_expected_root = true
	}
	// export time to (or since) expiration
	if time_since_expiry != start.Sub(start) {
		p.certExpiry.WithLabelValues(p.url).Set(-time_since_expiry.Seconds())
	} else {
		p.certExpiry.WithLabelValues(p.url).Set(time_to_expiry.Seconds())
	}

	return is_expected_root && is_expected_response, time.Since(start)
}
