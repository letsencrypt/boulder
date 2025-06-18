package acme

import (
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// GetRenewalInfo returns the renewal information (if present and supported by
// the ACME server), and a Retry-After time if indicated in the http response
// header.
func (c Client) GetRenewalInfo(cert *x509.Certificate) (RenewalInfo, error) {
	if c.dir.RenewalInfo == "" {
		return RenewalInfo{}, ErrRenewalInfoNotSupported
	}

	certID, err := GenerateARICertID(cert)
	if err != nil {
		return RenewalInfo{}, fmt.Errorf("acme: error generating certificate id: %v", err)
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
	defer resp.Body.Close()

	ri.RetryAfter, err = parseRetryAfter(resp.Header.Get("Retry-After"))
	return ri, err
}

// GenerateARICertID constructs a certificate identifier as described in
// draft-ietf-acme-ari-03, section 4.1.
func GenerateARICertID(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("certificate not found")
	}

	derBytes, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return "", err
	}

	if len(derBytes) < 3 {
		return "", fmt.Errorf("invalid DER encoding of serial number")
	}

	// Extract only the integer bytes from the DER encoded Serial Number
	// Skipping the first 2 bytes (tag and length). The result is base64url
	// encoded without padding.
	serial := base64.RawURLEncoding.EncodeToString(derBytes[2:])

	// Convert the Authority Key Identifier to base64url encoding without
	// padding.
	aki := base64.RawURLEncoding.EncodeToString(cert.AuthorityKeyId)

	// Construct the final identifier by concatenating AKI and Serial Number.
	return fmt.Sprintf("%s.%s", aki, serial), nil
}

func (r RenewalInfo) ShouldRenewAt(now time.Time, willingToSleep time.Duration) *time.Time {
	// Explicitly convert all times to UTC.
	now = now.UTC()
	start := r.SuggestedWindow.Start.UTC()
	end := r.SuggestedWindow.End.UTC()

	// Select a uniform random time within the suggested window.
	window := end.Sub(start)
	randomDuration := time.Duration(rand.Int63n(int64(window)))
	randomTime := start.Add(randomDuration)

	// If the selected time is in the past, attempt renewal immediately.
	if randomTime.Before(now) {
		return &now
	}

	// Otherwise, if the client can schedule itself to attempt renewal at
	// exactly the selected time, do so.
	willingToSleepUntil := now.Add(willingToSleep)
	if willingToSleepUntil.After(randomTime) || willingToSleepUntil.Equal(randomTime) {
		return &randomTime
	}

	return nil
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
