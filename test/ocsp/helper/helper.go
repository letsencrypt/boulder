package helper

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

var (
	method             = flag.String("method", "GET", "Method to use for fetching OCSP")
	urlOverride        = flag.String("url", "", "URL of OCSP responder to override")
	hostOverride       = flag.String("host", "", "Host header to override in HTTP request")
	tooSoon            = flag.Int("too-soon", 76, "If NextUpdate is fewer than this many hours in future, warn.")
	ignoreExpiredCerts = flag.Bool("ignore-expired-certs", false, "If a cert is expired, don't bother requesting OCSP.")
	expectStatus       = flag.Int("expect-status", -1, "Expect response to have this numeric status (0=Good, 1=Revoked, 2=Unknown); or -1 for no enforcement.")
	expectReason       = flag.Int("expect-reason", -1, "Expect response to have this numeric revocation reason (0=Unspecified, 1=KeyCompromise, etc); or -1 for no enforcement.")
)

// Config contains fields which control various behaviors of the
// checker's behavior.
type Config struct {
	method             string
	urlOverride        string
	hostOverride       string
	tooSoon            int
	ignoreExpiredCerts bool
	expectStatus       int
	expectReason       int
}

// DefaultConfig is a Config populated with the same defaults as if no
// command-line had been provided, so all retain their default value.
var DefaultConfig = Config{
	method:             *method,
	urlOverride:        *urlOverride,
	hostOverride:       *hostOverride,
	tooSoon:            *tooSoon,
	ignoreExpiredCerts: *ignoreExpiredCerts,
	expectStatus:       *expectStatus,
	expectReason:       *expectReason,
}

var parseFlagsOnce sync.Once

// ConfigFromFlags returns a Config whose values are populated from
// any command line flags passed by the user, or default values if not passed.
func ConfigFromFlags() Config {
	parseFlagsOnce.Do(func() {
		flag.Parse()
	})
	return Config{
		method:             *method,
		urlOverride:        *urlOverride,
		hostOverride:       *hostOverride,
		tooSoon:            *tooSoon,
		ignoreExpiredCerts: *ignoreExpiredCerts,
		expectStatus:       *expectStatus,
		expectReason:       *expectReason,
	}
}

// WithExpectStatus returns a new Config with the given expectStatus,
// and all other fields the same as the receiver.
func (template Config) WithExpectStatus(status int) Config {
	ret := template
	ret.expectStatus = status
	return ret
}

func getIssuer(cert *x509.Certificate) (*x509.Certificate, error) {
	if cert == nil {
		return nil, fmt.Errorf("nil certificate")
	}
	if len(cert.IssuingCertificateURL) == 0 {
		return nil, fmt.Errorf("No AIA information available, can't get issuer")
	}
	issuerURL := cert.IssuingCertificateURL[0]
	resp, err := http.Get(issuerURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var issuer *x509.Certificate
	contentType := resp.Header.Get("Content-Type")
	if contentType == "application/x-pkcs7-mime" || contentType == "application/pkcs7-mime" {
		issuer, err = parseCMS(body)
	} else {
		issuer, err = parse(body)
	}
	if err != nil {
		return nil, fmt.Errorf("from %s: %s", issuerURL, err)
	}
	return issuer, nil
}

func parse(body []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(body)
	var der []byte
	if block == nil {
		der = body
	} else {
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// parseCMS parses certificates from CMS messages of type SignedData.
func parseCMS(body []byte) (*x509.Certificate, error) {
	type signedData struct {
		Version          int
		Digests          asn1.RawValue
		EncapContentInfo asn1.RawValue
		Certificates     asn1.RawValue
	}
	type cms struct {
		ContentType asn1.ObjectIdentifier
		SignedData  signedData `asn1:"explicit,tag:0"`
	}
	var msg cms
	_, err := asn1.Unmarshal(body, &msg)
	if err != nil {
		return nil, fmt.Errorf("parsing CMS: %s", err)
	}
	cert, err := x509.ParseCertificate(msg.SignedData.Certificates.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CMS: %s", err)
	}
	return cert, nil
}

// Req makes an OCSP request using the given config for the PEM certificate in
// fileName, and returns the response.
func Req(fileName string, config Config) (*ocsp.Response, error) {
	contents, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return ReqDER(contents, config)
}

// ReqDER makes an OCSP request using the given config for the given DER-encoded
// certificate, and returns the response.
func ReqDER(der []byte, config Config) (*ocsp.Response, error) {
	cert, err := parse(der)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %s", err)
	}
	if time.Now().After(cert.NotAfter) {
		if config.ignoreExpiredCerts {
			return nil, nil
		} else {
			return nil, fmt.Errorf("certificate expired %s ago: %s",
				time.Since(cert.NotAfter), cert.NotAfter)
		}
	}

	issuer, err := getIssuer(cert)
	if err != nil {
		return nil, fmt.Errorf("getting issuer: %s", err)
	}
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("creating OCSP request: %s", err)
	}

	ocspURL, err := getOCSPURL(cert, config.urlOverride)
	if err != nil {
		return nil, err
	}

	httpResp, err := sendHTTPRequest(req, ocspURL, config.method, config.hostOverride)
	if err != nil {
		return nil, err
	}
	fmt.Printf("HTTP %d\n", httpResp.StatusCode)
	for k, v := range httpResp.Header {
		for _, vv := range v {
			fmt.Printf("%s: %s\n", k, vv)
		}
	}
	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("http status code %d", httpResp.StatusCode)
	}
	respBytes, err := ioutil.ReadAll(httpResp.Body)
	defer httpResp.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(respBytes) == 0 {
		return nil, fmt.Errorf("empty response body")
	}
	return parseAndPrint(respBytes, cert, issuer, config)
}

func sendHTTPRequest(req []byte, ocspURL *url.URL, method string, host string) (*http.Response, error) {
	encodedReq := base64.StdEncoding.EncodeToString(req)
	var httpRequest *http.Request
	var err error
	if method == "GET" {
		ocspURL.Path = encodedReq
		fmt.Printf("Fetching %s\n", ocspURL.String())
		httpRequest, err = http.NewRequest("GET", ocspURL.String(), http.NoBody)
	} else if method == "POST" {
		fmt.Printf("POSTing request, reproduce with: curl -i --data-binary @- %s < <(base64 -d <<<%s)\n",
			ocspURL, encodedReq)
		httpRequest, err = http.NewRequest("POST", ocspURL.String(), bytes.NewBuffer(req))
	} else {
		return nil, fmt.Errorf("invalid method %s, expected GET or POST", method)
	}
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	if host != "" {
		httpRequest.Host = host
	}
	client := http.Client{
		Timeout: 5 * time.Second,
	}

	return client.Do(httpRequest)
}

func getOCSPURL(cert *x509.Certificate, urlOverride string) (*url.URL, error) {
	var ocspServer string
	if urlOverride != "" {
		ocspServer = urlOverride
	} else if len(cert.OCSPServer) > 0 {
		ocspServer = cert.OCSPServer[0]
	} else {
		return nil, fmt.Errorf("no ocsp servers in cert")
	}
	ocspURL, err := url.Parse(ocspServer)
	if err != nil {
		return nil, fmt.Errorf("parsing URL: %s", err)
	}
	return ocspURL, nil
}

// checkSignerTimes checks that the OCSP response is within the
// validity window of whichever certificate signed it, and that that
// certificate is currently valid.
func checkSignerTimes(resp *ocsp.Response, issuer *x509.Certificate) error {
	var ocspSigner = issuer
	if delegatedSigner := resp.Certificate; delegatedSigner != nil {
		ocspSigner = delegatedSigner

		fmt.Printf("Using delegated OCSP signer from response: %s\n",
			base64.StdEncoding.EncodeToString(ocspSigner.Raw))
	}

	if resp.NextUpdate.After(ocspSigner.NotAfter) {
		return fmt.Errorf("OCSP response is valid longer than OCSP signer (%s): %s is after %s",
			ocspSigner.Subject, resp.NextUpdate, ocspSigner.NotAfter)
	}
	if resp.ThisUpdate.Before(ocspSigner.NotBefore) {
		return fmt.Errorf("OCSP response's validity begins before the OCSP signer's (%s): %s is before %s",
			ocspSigner.Subject, resp.ThisUpdate, ocspSigner.NotBefore)
	}

	if time.Now().After(ocspSigner.NotAfter) {
		return fmt.Errorf("OCSP signer (%s) expired at %s", ocspSigner.Subject, ocspSigner.NotAfter)
	}
	if time.Now().Before(ocspSigner.NotBefore) {
		return fmt.Errorf("OCSP signer (%s) not valid until %s", ocspSigner.Subject, ocspSigner.NotBefore)
	}
	return nil
}

func parseAndPrint(respBytes []byte, cert, issuer *x509.Certificate, config Config) (*ocsp.Response, error) {
	fmt.Printf("\nDecoding body: %s\n", base64.StdEncoding.EncodeToString(respBytes))
	resp, err := ocsp.ParseResponseForCert(respBytes, cert, issuer)
	if err != nil {
		return nil, fmt.Errorf("parsing response: %s", err)
	}

	var errs []error
	if config.expectStatus != -1 && resp.Status != config.expectStatus {
		errs = append(errs, fmt.Errorf("wrong CertStatus %d, expected %d", resp.Status, config.expectStatus))
	}
	if config.expectReason != -1 && resp.RevocationReason != config.expectReason {
		errs = append(errs, fmt.Errorf("wrong RevocationReason %d, expected %d", resp.RevocationReason, config.expectReason))
	}
	timeTilExpiry := time.Until(resp.NextUpdate)
	tooSoonDuration := time.Duration(config.tooSoon) * time.Hour
	if timeTilExpiry < tooSoonDuration {
		errs = append(errs, fmt.Errorf("NextUpdate is too soon: %s", timeTilExpiry))
	}

	err = checkSignerTimes(resp, issuer)
	if err != nil {
		errs = append(errs, fmt.Errorf("checking signature on delegated signer: %s", err))
	}

	fmt.Print("\n")
	fmt.Print("Response:\n")
	fmt.Printf("  CertStatus %d\n", resp.Status)
	fmt.Printf("  SerialNumber %036x\n", resp.SerialNumber)
	fmt.Printf("  ProducedAt %s\n", resp.ProducedAt)
	fmt.Printf("  ThisUpdate %s\n", resp.ThisUpdate)
	fmt.Printf("  NextUpdate %s\n", resp.NextUpdate)
	fmt.Printf("  RevokedAt %s\n", resp.RevokedAt)
	fmt.Printf("  RevocationReason %d\n", resp.RevocationReason)
	fmt.Printf("  SignatureAlgorithm %s\n", resp.SignatureAlgorithm)
	fmt.Printf("  Extensions %#v\n", resp.Extensions)
	if resp.Certificate == nil {
		fmt.Print("  Certificate: nil\n")
	} else {
		fmt.Print("  Certificate:\n")
		fmt.Printf("    Subject: %s\n", resp.Certificate.Subject)
		fmt.Printf("    Issuer: %s\n", resp.Certificate.Issuer)
		fmt.Printf("    NotBefore: %s\n", resp.Certificate.NotBefore)
		fmt.Printf("    NotAfter: %s\n", resp.Certificate.NotAfter)
	}

	if len(errs) > 0 {
		fmt.Print("Errors:\n")
		err := errs[0]
		fmt.Printf("  %v\n", err.Error())
		for _, e := range errs[1:] {
			err = fmt.Errorf("%w; %v", err, e)
			fmt.Printf("  %v\n", e.Error())
		}
		return nil, err
	}
	fmt.Print("No errors found.\n")
	return resp, nil
}
