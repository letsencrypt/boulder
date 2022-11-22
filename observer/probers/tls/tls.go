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

func (e badOutcomeError) Error() string {
	return reasonToString[e.reason]
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
	url      string
	rootOrg  string
	rootCN   string
	response string
	notAfter *prometheus.GaugeVec
	reason   *prometheus.GaugeVec
}

// Name returns a string that uniquely identifies the monitor.
func (p TLSProbe) Name() string {
	return fmt.Sprintf("%s-expecting-%s-%s-%s", p.url, p.response, p.rootOrg, p.rootCN)
}

// Kind returns a name that uniquely identifies the `Kind` of `Prober`.
func (p TLSProbe) Kind() string {
	return "TLS"
}

// Get OCSP status (good, revoked or unknown) of certificate
func getOCSPStatus(cert, issuer *x509.Certificate) (int, error) {
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return ocsp.Unknown, err
	}

	url := fmt.Sprintf("%s/%s", cert.OCSPServer[0], base64.StdEncoding.EncodeToString(req))
	res, err := http.Get(url)
	if err != nil {
		return ocsp.Unknown, err
	}

	output, err := io.ReadAll(res.Body)
	if err != nil {
		return ocsp.Unknown, err
	}

	ocspRes, err := ocsp.ParseResponseForCert(output, cert, issuer)
	if err != nil {
		return ocsp.Unknown, err
	}

	switch ocspRes.Status {
	case ocsp.Revoked:
		return ocsp.Revoked, nil
	case ocsp.Good:
		return ocsp.Good, nil
	default:
		return ocsp.Unknown, nil
	}
}

// Make a TLS connection with InsecureSkipVerify set to true to get the
// expiration time and root information of insecure leaf certificates.
func (p TLSProbe) getInsecureCertInfo() (string, string, time.Time, error) {
	conf := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", p.url+":443", conf)
	if err != nil {
		return "", "", time.Time{}, err
	}
	peers := conn.ConnectionState().PeerCertificates

	for i := 0; i < len(peers)-1; i++ {
		certIssuer, issuerSubject := peers[i].Issuer, peers[i+1].Subject
		if (certIssuer.CommonName != issuerSubject.CommonName) || (certIssuer.Organization[0] != issuerSubject.Organization[0]) {
			err = fmt.Errorf(reasonToString[issuerVerifyFailed])
		}
	}

	root := peers[len(peers)-1].Issuer
	return root.Organization[0], root.CommonName, peers[0].NotAfter, err
}

// Check if the root of the leaf's certificate is the one we expect.
func (p TLSProbe) isRootExpected(rootO, rootCN string) bool {
	if p.rootOrg == rootO && p.rootCN == rootCN {
		return true
	}
	return false
}

// Export expiration timestamp and reason (with corresponding badOutcome label)
// to Prometheus.
func (p TLSProbe) exportMetrics(notAfter time.Time, reason reason) {
	p.notAfter.WithLabelValues(p.url).Set(float64(notAfter.Unix()))
	p.notAfter.WithLabelValues(p.url, badOutcomeError{reason}.Error()).Set(float64(reason))
}

// Probe performs the configured TLS protocol. Return true if both root AND
// response are the expected values, otherwise false. Export expiration
// timestamp and reason as Prometheus metrics.
func (p TLSProbe) Probe(timeout time.Duration) (bool, time.Duration) {
	start := time.Now()
	conn, secure_err := tls.Dial("tcp", p.url+":443", &tls.Config{})
	if secure_err != nil {
		// TLS connection failed, so try insecure connection instead.
		rootO, rootCN, notAfter, err := p.getInsecureCertInfo()
		// Insecure connection successful, but certificate chain is invalid.
		if errors.Is(err, fmt.Errorf(reasonToString[issuerVerifyFailed])) {
			p.exportMetrics(notAfter, issuerVerifyFailed)
			return false, time.Since(start)
		}
		// Insecure connection failed.
		if err != nil {
			p.exportMetrics(notAfter, internalError)
			return false, time.Since(start)
		}
		// Insecure connection successful and chain is valid, so check if
		// certificate is and should be expired.
		if p.response == "expired" {
			certInvalidErr := x509.CertificateInvalidError{}
			p.exportMetrics(notAfter, none)
			return (errors.As(secure_err, &certInvalidErr) && certInvalidErr.Reason == x509.Expired) && p.isRootExpected(rootO, rootCN), time.Since(start)
		}
		// None of the above cases. Secure TLS connection failed and certificate
		// should not be expired, so return false.
		p.exportMetrics(notAfter, internalError)
		return false, time.Since(start)
	}
	// Certificate has been validated. Now check if it's revoked.
	defer conn.Close()
	chains := conn.ConnectionState().VerifiedChains
	leaf, issuer, rootCert := chains[0][0], chains[0][1], chains[0][len(chains[0])-1].Issuer
	notAfter := leaf.NotAfter
	rootO, rootCN := rootCert.Organization[0], rootCert.CommonName

	// Check OCSP to see if the certificate is valid, revoked or unknown.
	ocspStatus, err := getOCSPStatus(leaf, issuer)
	if err != nil {
		p.exportMetrics(notAfter, ocspError)
		return false, time.Since(start)
	}
	if ocspStatus == ocsp.Unknown {
		p.exportMetrics(notAfter, ocspUnknown)
		return false, time.Since(start)
	}

	p.exportMetrics(notAfter, none)
	return ((p.response == "revoked" && ocspStatus == ocsp.Revoked) || (p.response == "valid" && ocspStatus == ocsp.Good)) && (p.isRootExpected(rootO, rootCN)), time.Since(start)
}
