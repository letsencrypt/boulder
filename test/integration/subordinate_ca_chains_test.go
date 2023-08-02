//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestSubordinateCAChainsServedByWFE(t *testing.T) {
	t.Parallel()

	// Create an account.
	client, err := makeClient("mailto:example@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")

	// Create a private key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "creating random cert key")

	// Issue a cert
	name := random_domain()
	_, err = authAndIssueFetchAllChains(client, key, []string{name}, true)
	test.AssertNotError(t, err, "failed to issue test cert")

	/*
		cert := ir.certs[0]
		_, err = ocsp_helper.GetIssuer(cert)
		test.AssertNotError(t, err, "failed to get issuer cert")
	*/
}
