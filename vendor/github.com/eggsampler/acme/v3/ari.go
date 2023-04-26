package acme

import (
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type (
	// RenewalInfo is returned by Client.GetRenewalInfo
	RenewalInfo struct {
		SuggestedWindow struct {
			Start time.Time `json:"start"`
			End   time.Time `json:"end"`
		} `json:"suggestedWindow"`
		ExplanationURL string `json:"explanationURL"`

		RetryAfter time.Time `json:"-"`
	}
)

var (
	// ErrRenewalInfoNotSupported is returned by Client.GetRenewalInfo and Client.UpdateRenewalInfo if the renewal info
	// entry isn't present on the acme directory (ie, it's not supported by the acme server)
	ErrRenewalInfoNotSupported = errors.New("renewal information endpoint not")

	// from https://cs.opensource.google/go/x/crypto/+/refs/tags/v0.8.0:ocsp/ocsp.go;l=156
	hashOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
		crypto.SHA1:   asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26}),
		crypto.SHA256: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1}),
		crypto.SHA384: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 2}),
		crypto.SHA512: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3}),
	}

	// hashNames exists because go 1.11 doesn't have crypto.Hash.String()
	hashNames = map[crypto.Hash]string{
		crypto.SHA1:   "SHA1",
		crypto.SHA256: "SHA256",
		crypto.SHA384: "SHA384",
		crypto.SHA512: "SHA512",
	}
)

// GetRenewalInfo returns the renewal information (if present and supported by the ACME server), and
// a Retry-After time if indicated in the http response header.
func (c Client) GetRenewalInfo(cert, issuer *x509.Certificate, hash crypto.Hash) (RenewalInfo, error) {

	if len(c.dir.RenewalInfo) == 0 {
		return RenewalInfo{}, ErrRenewalInfoNotSupported
	}

	certID, err := generateCertID(cert, issuer, hash)
	if err != nil {
		return RenewalInfo{}, fmt.Errorf("error generating certificate id: %v", err)
	}

	renewalURL := c.dir.RenewalInfo
	if !strings.HasSuffix(renewalURL, "/") {
		renewalURL += "/"
	}
	renewalURL += certID
	var ri RenewalInfo

	resp, err := c.get(renewalURL, &ri, http.StatusOK)
	if err != nil {
		return ri, err
	}

	ri.RetryAfter, err = parseRetryAfter(resp.Header.Get("Retry-After"))
	return ri, err
}

// UpdateRenewalInfo sends a request to the acme server to indicate the renewal info is updated.
// replaced should always be true.
func (c Client) UpdateRenewalInfo(account Account, cert, issuer *x509.Certificate, hash crypto.Hash, replaced bool) error {

	if len(c.dir.RenewalInfo) == 0 {
		return ErrRenewalInfoNotSupported
	}

	certID, err := generateCertID(cert, issuer, hash)
	if err != nil {
		return fmt.Errorf("error generating certificate id: %v", err)
	}

	updateReq := struct {
		CertID   string `json:"certID"`
		Replaced bool   `json:"replaced"`
	}{
		CertID:   certID,
		Replaced: replaced,
	}

	_, err = c.post(c.dir.RenewalInfo, account.URL, account.PrivateKey, updateReq, nil, http.StatusOK)

	return err
}

// generateCertID creates a CertID as per RFC6960
func generateCertID(cert, issuer *x509.Certificate, hashFunc crypto.Hash) (string, error) {
	oid, ok := hashOIDs[hashFunc]
	if !ok {
		var s []string
		for k := range hashOIDs {
			s = append(s, hashNames[k])
		}
		return "", fmt.Errorf("unsupported hash algorithm %q, currently available: %q", hashNames[hashFunc], strings.Join(s, ","))
	}

	if !hashFunc.Available() {
		return "", x509.ErrUnsupportedAlgorithm
	}

	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return "", err
	}

	h := hashFunc.New()
	h.Write(issuer.RawSubject)
	issuerNameHash := h.Sum(nil)

	h.Reset()
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	issuerKeyHash := h.Sum(nil)

	s := struct {
		HashAlgorithm  pkix.AlgorithmIdentifier
		IssuerNameHash []byte
		IssuerKeyHash  []byte
		SerialNumber   *big.Int
	}{
		HashAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oid,
			// Parameters: asn1.RawValue{Tag: 5 /* ASN.1 NULL */},
		},
		IssuerNameHash: issuerNameHash,
		IssuerKeyHash:  issuerKeyHash,
		SerialNumber:   cert.SerialNumber,
	}
	b, err := asn1.Marshal(s)
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "="), err
}

// timeNow and implementations support testing
type timeNow interface {
	Now() time.Time
}

type currentTimeNow struct{}

func (currentTimeNow) Now() time.Time {
	return time.Now()
}

var systemTime timeNow = currentTimeNow{}

func parseRetryAfter(ra string) (time.Time, error) {
	retryAfterString := strings.TrimSpace(ra)
	if len(retryAfterString) == 0 {
		return time.Time{}, nil
	}

	if retryAfterTime, err := time.Parse(time.RFC1123, retryAfterString); err == nil {
		return retryAfterTime, nil
	}

	if retryAfterInt, err := strconv.Atoi(retryAfterString); err == nil {
		return systemTime.Now().Add(time.Second * time.Duration(retryAfterInt)), nil
	}

	return time.Time{}, fmt.Errorf("invalid time format: %s", retryAfterString)
}
