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
	"time"

	"golang.org/x/crypto/ocsp"
)

var method = flag.String("method", "GET", "Method to use for fetching OCSP")
var urlOverride = flag.String("url", "", "URL of OCSP responder to override")
var hostOverride = flag.String("host", "", "Host header to override in HTTP request")
var tooSoon = flag.Int("too-soon", 76, "If NextUpdate is fewer than this many hours in future, warn.")
var ignoreExpiredCerts = flag.Bool("ignore-expired-certs", false, "If a cert is expired, don't bother requesting OCSP.")
var expectStatus = flag.Int("expect-status", 0, "Expect response to have this numeric status (0=good, 1=revoked)")

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
	if resp.Header.Get("Content-Type") == "application/x-pkcs7-mime" {
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
	cert, err := x509.ParseCertificate(msg.SignedData.Certificates.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CMS: %s", err)
	}
	return cert, nil
}

func Req(fileName string) (*ocsp.Response, error) {
	contents, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	cert, err := parse(contents)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %s", err)
	}
	if time.Now().After(cert.NotAfter) {
		if *ignoreExpiredCerts {
			return nil, nil
		} else {
			return nil, fmt.Errorf("certificate expired %s ago: %s",
				time.Now().Sub(cert.NotAfter), cert.NotAfter)
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

	ocspURL, err := getOCSPURL(cert)
	if err != nil {
		return nil, err
	}

	http.DefaultClient.Timeout = 5 * time.Second

	httpResp, err := sendHTTPRequest(req, ocspURL)
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
		return nil, fmt.Errorf("empty reponse body")
	}
	return parseAndPrint(respBytes, cert, issuer)
}

func sendHTTPRequest(req []byte, ocspURL *url.URL) (*http.Response, error) {
	encodedReq := base64.StdEncoding.EncodeToString(req)
	var httpRequest *http.Request
	var err error
	if *method == "GET" {
		ocspURL.Path = encodedReq
		fmt.Printf("Fetching %s\n", ocspURL.String())
		httpRequest, err = http.NewRequest("GET", ocspURL.String(), http.NoBody)
	} else if *method == "POST" {
		fmt.Printf("POSTing request, reproduce with: curl -i --data-binary @- %s < <(base64 -d <<<%s)\n",
			ocspURL, encodedReq)
		httpRequest, err = http.NewRequest("POST", ocspURL.String(), bytes.NewBuffer(req))
	} else {
		return nil, fmt.Errorf("invalid method %s, expected GET or POST", *method)
	}
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	if *hostOverride != "" {
		httpRequest.Host = *hostOverride
	}
	return http.DefaultClient.Do(httpRequest)
}

func getOCSPURL(cert *x509.Certificate) (*url.URL, error) {
	var ocspServer string
	if *urlOverride != "" {
		ocspServer = *urlOverride
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

func parseAndPrint(respBytes []byte, cert, issuer *x509.Certificate) (*ocsp.Response, error) {
	fmt.Printf("\nDecoding body: %s\n", base64.StdEncoding.EncodeToString(respBytes))
	resp, err := ocsp.ParseResponseForCert(respBytes, cert, issuer)
	if err != nil {
		return nil, fmt.Errorf("parsing response: %s", err)
	}
	if resp.Status != *expectStatus {
		return nil, fmt.Errorf("wrong CertStatus %d, expected %d", resp.Status, *expectStatus)
	}
	timeTilExpiry := time.Until(resp.NextUpdate)
	tooSoonDuration := time.Duration(*tooSoon) * time.Hour
	if timeTilExpiry < tooSoonDuration {
		return nil, fmt.Errorf("NextUpdate is too soon: %s", timeTilExpiry)
	}
	fmt.Printf("\n")
	fmt.Printf("Good response:\n")
	fmt.Printf("  CertStatus %d\n", resp.Status)
	fmt.Printf("  SerialNumber %036x\n", resp.SerialNumber)
	fmt.Printf("  ProducedAt %s\n", resp.ProducedAt)
	fmt.Printf("  ThisUpdate %s\n", resp.ThisUpdate)
	fmt.Printf("  NextUpdate %s\n", resp.NextUpdate)
	fmt.Printf("  RevokedAt %s\n", resp.RevokedAt)
	fmt.Printf("  RevocationReason %d\n", resp.RevocationReason)
	fmt.Printf("  SignatureAlgorithm %s\n", resp.SignatureAlgorithm)
	fmt.Printf("  Extensions %#v\n", resp.Extensions)
	return resp, nil
}
