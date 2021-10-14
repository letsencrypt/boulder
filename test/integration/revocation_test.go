//go:build integration
// +build integration

package integration

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eggsampler/acme/v3"
	"github.com/letsencrypt/boulder/test"
	ocsp_helper "github.com/letsencrypt/boulder/test/ocsp/helper"
	"golang.org/x/crypto/ocsp"
)

// isPrecert returns true if the provided cert has an extension with the OID
// equal to OIDExtensionCTPoison.
func isPrecert(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDExtensionCTPoison) {
			return true
		}
	}
	return false
}

// TestPrecertificateRevocation tests that a precertificate without a matching
// certificate can be revoked using all of the available RFC 8555 revocation
// authentication mechanisms.
func TestPrecertificateRevocation(t *testing.T) {
	t.Parallel()
	// Create a base account to use for revocation tests.
	os.Setenv("DIRECTORY", "http://boulder:4001/directory")
	c, err := makeClient("mailto:example@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")

	// Create a specific key for CSRs so that it is possible to test revocation
	// with the cert key.
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "creating random cert key")

	// Create a second account to test revocation with an equally authorized account
	otherAccount, err := makeClient()
	test.AssertNotError(t, err, "creating second acme client")
	// Preauthorize a specific domain with the other account before it has been
	// added to the ct-test-srv reject list.
	preAuthDomain := random_domain()
	_, err = authAndIssue(otherAccount, nil, []string{preAuthDomain})
	test.AssertNotError(t, err, "preauthorizing second acme client")

	testCases := []struct {
		name         string
		domain       string
		revokeClient *client
		revokeKey    crypto.Signer
	}{
		{
			name:      "revocation by certificate key",
			revokeKey: certKey,
		},
		{
			name:      "revocation by owner account key",
			revokeKey: c.Account.PrivateKey,
		},
		{
			name:         "equivalently authorized account key",
			revokeClient: otherAccount,
			revokeKey:    otherAccount.Account.PrivateKey,
			domain:       preAuthDomain,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// If the test case didn't specify a domain make one up randomly
			if tc.domain == "" {
				tc.domain = random_domain()
			}
			// If the test case didn't specify a different client to use for
			// revocation use c.
			if tc.revokeClient == nil {
				tc.revokeClient = c
			}

			// Make sure the ct-test-srv will reject issuance for the domain
			err := ctAddRejectHost(tc.domain)
			test.AssertNotError(t, err, "adding ct-test-srv reject host")

			// Issue a certificate for the name using the `c` client. It should fail
			// because not enough SCTs can be collected, leaving a precert without
			// a matching final cert.
			_, err = authAndIssue(c, certKey, []string{tc.domain})
			test.AssertError(t, err, "expected error from authAndIssue, was nil")
			if !strings.Contains(err.Error(), "urn:ietf:params:acme:error:serverInternal") ||
				!strings.Contains(err.Error(), "SCT embedding") {
				t.Fatal(err)
			}

			// Try to find a precertificate matching the domain from one of the
			// configured ct-test-srv instances.
			cert, err := ctFindRejection([]string{tc.domain})
			if err != nil || cert == nil {
				t.Fatalf("couldn't find rejected precert for %q", tc.domain)
			}

			// To be confident that we're testing the right thing also verify that the
			// rejection is a poisoned precertificate.
			if !isPrecert(cert) {
				t.Fatal("precert was missing poison extension")
			}

			// To start with the precertificate should have a Good OCSP response.
			ocspConfig := ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Good)
			_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
			test.AssertNotError(t, err, "requesting OCSP for precert")

			// Revoke the precertificate using the specified key and client
			err = tc.revokeClient.RevokeCertificate(
				tc.revokeClient.Account,
				cert,
				tc.revokeKey,
				ocsp.Unspecified)
			test.AssertNotError(t, err, "revoking precert")

			// Check the OCSP response for the precertificate again. It should now be
			// revoked.
			ocspConfig = ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Revoked)
			_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
			test.AssertNotError(t, err, "requesting OCSP for revoked precert")
		})
	}
}

func TestRevokeWithKeyCompromise(t *testing.T) {
	t.Parallel()
	os.Setenv("DIRECTORY", "http://boulder:4001/directory")
	c, err := makeClient("mailto:example@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate cert key")

	res, err := authAndIssue(c, certKey, []string{random_domain()})
	test.AssertNotError(t, err, "authAndIssue failed")

	cert := res.certs[0]

	err = c.RevokeCertificate(
		acme.Account{},
		cert,
		certKey,
		ocsp.KeyCompromise,
	)
	test.AssertNotError(t, err, "failed to revoke certificate")

	// attempt to create a new account using the blacklisted key
	_, err = c.NewAccount(certKey, false, true)
	test.AssertError(t, err, "NewAccount didn't fail with a blacklisted key")
	test.AssertEquals(t, err.Error(), `acme: error code 400 "urn:ietf:params:acme:error:badPublicKey": public key is forbidden`)

	// Check the OCSP response. It should be revoked with reason = 1 (keyCompromise)
	ocspConfig := ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Revoked)
	response, err := ocsp_helper.ReqDER(cert.Raw, ocspConfig)
	test.AssertNotError(t, err, "requesting OCSP for revoked cert")
	test.AssertEquals(t, response.RevocationReason, 1)
}

func TestBadKeyRevoker(t *testing.T) {
	t.Parallel()
	os.Setenv("DIRECTORY", "http://boulder:4001/directory")
	cA, err := makeClient("mailto:bad-key-revoker-revoker@letsencrypt.org", "mailto:bad-key-revoker-revoker-2@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")
	cB, err := makeClient("mailto:bad-key-revoker-revoker-2@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")
	cC, err := makeClient("mailto:bad-key-revoker-revokee@letsencrypt.org", "mailto:bad-key-revoker-revokee-2@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")
	cD, err := makeClient("mailto:bad-key-revoker-revokee-2@letsencrypt.org", "mailto:bad-key-revoker-revokee@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")
	cE, err := makeClient()
	test.AssertNotError(t, err, "creating acme client")

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate cert key")

	badCert, err := authAndIssue(cA, certKey, []string{random_domain()})
	test.AssertNotError(t, err, "authAndIssue failed")

	certs := []*x509.Certificate{}
	for _, c := range []*client{cA, cB, cC, cD, cE} {
		for i := 0; i < 2; i++ {
			cert, err := authAndIssue(c, certKey, []string{random_domain()})
			test.AssertNotError(t, err, "authAndIssue failed")
			certs = append(certs, cert.certs[0])
		}
	}

	err = cA.RevokeCertificate(
		acme.Account{},
		badCert.certs[0],
		certKey,
		ocsp.KeyCompromise,
	)
	test.AssertNotError(t, err, "failed to revoke certificate")
	ocspConfig := ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Revoked)
	_, err = ocsp_helper.ReqDER(badCert.certs[0].Raw, ocspConfig)
	test.AssertNotError(t, err, "ReqDER failed")

	for _, cert := range certs {
		for i := 0; i < 5; i++ {
			_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
			if err == nil {
				break
			}
			if i == 5 {
				t.Fatal("timed out waiting for revoked OCSP status")
			}
			time.Sleep(time.Second)
		}
	}

	countResp, err := http.Get("http://boulder:9381/count?to=bad-key-revoker-revokee@letsencrypt.org")
	test.AssertNotError(t, err, "mail-test-srv GET /count failed")
	defer func() { _ = countResp.Body.Close() }()
	body, err := ioutil.ReadAll(countResp.Body)
	test.AssertNotError(t, err, "failed to read body")
	test.AssertEquals(t, string(body), "1\n")
	otherCountResp, err := http.Get("http://boulder:9381/count?to=bad-key-revoker-revokee-2@letsencrypt.org")
	test.AssertNotError(t, err, "mail-test-srv GET /count failed")
	defer func() { _ = otherCountResp.Body.Close() }()
	body, err = ioutil.ReadAll(otherCountResp.Body)
	test.AssertNotError(t, err, "failed to read body")
	test.AssertEquals(t, string(body), "1\n")

	zeroCountResp, err := http.Get("http://boulder:9381/count?to=bad-key-revoker-revoker@letsencrypt.org")
	test.AssertNotError(t, err, "mail-test-srv GET /count failed")
	defer func() { _ = zeroCountResp.Body.Close() }()
	body, err = ioutil.ReadAll(zeroCountResp.Body)
	test.AssertNotError(t, err, "failed to read body")
	test.AssertEquals(t, string(body), "1\n")
}
