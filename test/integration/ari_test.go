//go:build integration

package integration

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/eggsampler/acme/v3"

	"github.com/letsencrypt/boulder/test"
	ocsp_helper "github.com/letsencrypt/boulder/test/ocsp/helper"
)

// certID matches the ASN.1 structure of the CertID sequence defined by RFC6960.
type certID struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

func TestARI(t *testing.T) {
	t.Parallel()

	// Create an account.
	client, err := makeClient("mailto:example@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")

	// Create a private key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "creating random cert key")

	// Issue a cert, request ARI, and check that both the suggested window and
	// the retry-after header are approximately the right amount of time in the
	// future.
	name := random_domain()
	ir, err := authAndIssue(client, key, []string{name}, true)
	test.AssertNotError(t, err, "failed to issue test cert")

	cert := ir.certs[0]
	issuer, err := ocsp_helper.GetIssuer(cert)
	test.AssertNotError(t, err, "failed to get issuer cert")

	eri, err := client.GetRenewalInfo(cert, issuer, crypto.SHA256)
	test.AssertNotError(t, err, "ARI request should have succeeded")
	test.AssertEquals(t, eri.SuggestedWindow.Start.Sub(time.Now()).Round(time.Hour), 1415*time.Hour)
	test.AssertEquals(t, eri.SuggestedWindow.End.Sub(time.Now()).Round(time.Hour), 1463*time.Hour)
	test.AssertEquals(t, eri.RetryAfter.Sub(time.Now()).Round(time.Hour), 6*time.Hour)

	// Revoke the cert, re-request ARI, and the window should now be in the past.
	err = client.RevokeCertificate(client.Account, cert, client.PrivateKey, 0)
	test.AssertNotError(t, err, "failed to revoke cert")

	eri, err = client.GetRenewalInfo(cert, issuer, crypto.SHA256)
	test.AssertNotError(t, err, "ARI request should have succeeded")
	test.Assert(t, eri.SuggestedWindow.End.Before(time.Now()), "suggested window should end in the past")
	test.Assert(t, eri.SuggestedWindow.Start.Before(eri.SuggestedWindow.End), "suggested window should start before it ends")

	// Check that marking the cert as replaced succeeds, but don't check that
	// any server state has been updated (because that doesn't happen, yet).
	err = client.UpdateRenewalInfo(client.Account, cert, issuer, crypto.SHA256, true)
	test.AssertNotError(t, err, "ARI request should have succeeded")

	// Try to make a new cert for a new domain, but sabotage the CT logs so
	// issuance fails. Recover the precert from CT, then request ARI and check
	// that it fails, because we don't serve ARI for non-issued certs.
	name = random_domain()
	err = ctAddRejectHost(name)
	test.AssertNotError(t, err, "failed to add ct-test-srv reject host")
	_, err = authAndIssue(client, key, []string{name}, true)
	test.AssertError(t, err, "expected error from authAndIssue, was nil")

	cert, err = ctFindRejection([]string{name})
	test.AssertNotError(t, err, "failed to find rejected precert")
	issuer, err = ocsp_helper.GetIssuer(cert)
	test.AssertNotError(t, err, "failed to get issuer cert")

	eri, err = client.GetRenewalInfo(cert, issuer, crypto.SHA256)
	test.AssertError(t, err, "ARI request should have failed")
	test.AssertEquals(t, err.(acme.Problem).Status, 404)
}
