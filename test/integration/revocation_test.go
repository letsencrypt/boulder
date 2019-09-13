// +build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/test"
	ocsp_helper "github.com/letsencrypt/boulder/test/ocsp/helper"
	"golang.org/x/crypto/ocsp"
)

func TestPrecertificateRevocation(t *testing.T) {
	// This test is gated on the PrecertificateRevocation feature flag.
	if !strings.Contains(os.Getenv("BOULDER_CONFIG_DIR"), "test/config-next") {
		return
	}

	// Pick a random domain, make sure all of the ct-test-srv's reject giving back
	// SCTs for that domain.
	domain := random_domain()
	ctAddRejectHost(t, domain)

	os.Setenv("DIRECTORY", "http://boulder:4001/directory")
	c, err := makeClient()
	test.AssertNotError(t, err, "unexpected error creating acme client")

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "unexpected error creating random cert key")

	// Issue a certificate for the name. It should fail because not enough SCTs
	// can be collected, leaving a precert without a matching final cert.
	_, err = authAndIssue(c, certKey, []string{domain})
	test.AssertError(t, err, "expected error from authAndIssue, was nil")
	if !strings.Contains(err.Error(), "urn:ietf:params:acme:error:serverInternal") ||
		!strings.Contains(err.Error(), "SCT embedding") {
		t.Fatal(err)
	}

	// Get the rejections from the first ct-test-srv
	rejections := ctGetRejections(t, 4500)
	if len(rejections) == 0 {
		t.Fatal("expected to find rejected precert from ct-test-srv:4500, found none")
	}

	// Parse the rejections and find the precertificate that matches the random
	// domain we issued for.
	var cert *x509.Certificate
	for _, r := range rejections {
		precertDER, err := base64.StdEncoding.DecodeString(r)
		test.AssertNotError(t, err, "unexpected error decoding ct-test-srv rejected precert bytes")
		c, err := x509.ParseCertificate(precertDER)
		test.AssertNotError(t, err, "unexpected error parsing ct-test-srv rejected precert bytes")

		if len(c.DNSNames) == 1 && c.DNSNames[0] == domain {
			cert = c
		}
	}
	// If there was no matching precert then fail the test
	if cert == nil {
		t.Fatalf("failed to find precertificate for %q in ct-test-srv:4500 rejections", domain)
	}

	// To be confident that we're testing the right thing also verify that the
	// rejection is a poisoned precertificate.
	var isPrecert bool
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDExtensionCTPoison) {
			isPrecert = true
			break
		}
	}
	test.AssertEquals(t, isPrecert, true)

	// To start with the precertificate should have a Good OCSP response.
	_, err = ocsp_helper.ReqDER(cert.Raw, ocsp.Good)
	test.AssertNotError(t, err, "unexpected error requesting OCSP for precert")

	// Revoke the precertificate
	err = c.RevokeCertificate(c.Account, cert, certKey, ocsp.KeyCompromise)
	test.AssertNotError(t, err, "unexpected error revoking precert")

	// Check the OCSP response for the precertificate again. It should now be
	// revoked.
	_, err = ocsp_helper.ReqDER(cert.Raw, ocsp.Revoked)
	test.AssertNotError(t, err, "unexpected error requesting OCSP for revoked precert")
}
