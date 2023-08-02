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

	client, err := makeClient("mailto:example@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "creating random cert key")

	name := random_domain()
	chains, err := authAndIssueFetchAllChains(client, key, []string{name}, true)
	test.AssertNotError(t, err, "failed to issue test cert")

	// An ECDSA intermediate signed by an ECDSA root, and an ECDSA cross-signed by an RSA root.
	test.AssertEquals(t, len(chains.certs), 2)

	seenECDSAIntermediate := false
	seenECDSASubordinate := false
	for _, certUrl := range chains.certs {
		for _, cert := range certUrl {
			if cert.Subject.String() == "CN=CA intermediate (ECDSA) A,O=good guys,C=US" && cert.Issuer.String() == "CN=CA root (ECDSA),O=good guys,C=US" {
				seenECDSAIntermediate = true
			}
			if cert.Subject.String() == "CN=CA intermediate (ECDSA) A,O=good guys,C=US" && cert.Issuer.String() == "CN=CA root (RSA),O=good guys,C=US" {
				seenECDSASubordinate = true
			}
		}
	}
	test.Assert(t, seenECDSAIntermediate, "did not see ECDSA intermediate and should have")
	test.Assert(t, seenECDSASubordinate, "did not see ECDSA by RSA cross-signed subordinate and should have")
}
