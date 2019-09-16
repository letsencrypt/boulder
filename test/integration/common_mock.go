// +build integration

package integration

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

// ctAddRejectHost adds a domain to all of the CT test server's reject-host
// lists. If this fails the test is aborted with a fatal error.
func ctAddRejectHost(t *testing.T, domain string) {
	for _, port := range []int{4500, 4501, 4510, 4511} {
		url := fmt.Sprintf("http://boulder:%d/add-reject-host", port)
		body := []byte(fmt.Sprintf(`{"host": %q}`, domain))
		resp, err := http.Post(url, "", bytes.NewBuffer(body))
		if err != nil {
			t.Fatalf("adding reject host: %s", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("adding reject host: %d", resp.StatusCode)
		}
		resp.Body.Close()
	}
}

// ctGetRejections returns a slice of base64 encoded certificates that were
// rejected by the CT test server at the specified port. If this fails the test
// is aborted with a fatal error.
func ctGetRejections(t *testing.T, port int) []string {
	url := fmt.Sprintf("http://boulder:%d/get-rejections", port)
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("getting rejections: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("getting rejections: status %d", resp.StatusCode)
	}
	var rejections []string
	err = json.NewDecoder(resp.Body).Decode(&rejections)
	if err != nil {
		t.Fatalf("parsing rejections: %s", err)
	}
	return rejections
}

// ctFindRejection returns a parsed x509.Certificate matching the given domains
// from the base64 certificates the CT test server rejected. If no rejected
// certificate matching the provided domains is found the test is failed.
func ctFindRejection(t *testing.T, port int, domains []string) *x509.Certificate {
	// Parse each rejection cert
	var cert *x509.Certificate
RejectionLoop:
	for _, r := range ctGetRejections(t, port) {
		precertDER, err := base64.StdEncoding.DecodeString(r)
		test.AssertNotError(t, err, "unexpected error decoding ct-test-srv rejected precert bytes")
		c, err := x509.ParseCertificate(precertDER)
		test.AssertNotError(t, err, "unexpected error parsing ct-test-srv rejected precert bytes")
		// If the cert doesn't have the right number of names it won't be a match.
		if len(c.DNSNames) != len(domains) {
			continue
		}
		// If any names don't match, it isn't a match
		for i, name := range c.DNSNames {
			if name != domains[i] {
				continue RejectionLoop
			}
		}
		// It's a match!
		cert = c
		break
	}
	if cert == nil {
		// If we end the loop without having returned a cert the test should fail.
		t.Fatalf("failed to find precertificate for %s in ct-test-srv:%d rejections",
			strings.Join(domains, ", "), port)
	}
	return cert
}
