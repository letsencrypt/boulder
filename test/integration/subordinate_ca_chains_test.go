//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestSubordinateCAChainsServedByWFE(t *testing.T) {
	t.Parallel()

	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		t.Skip("Skipping test in config")
	}

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
	seenECDSACrossSignedIntermediate := false
	for _, certUrl := range chains.certs {
		for _, cert := range certUrl {
			if cert.Subject.String() == "CN=int ecdsa a,O=good guys,C=US" && cert.Issuer.String() == "CN=root ecdsa,O=good guys,C=US" {
				seenECDSAIntermediate = true
			}
			if cert.Subject.String() == "CN=int ecdsa a,O=good guys,C=US" && cert.Issuer.String() == "CN=root rsa,O=good guys,C=US" {
				seenECDSACrossSignedIntermediate = true
			}
		}
	}
	test.Assert(t, seenECDSAIntermediate, "did not see ECDSA intermediate and should have")
	test.Assert(t, seenECDSACrossSignedIntermediate, "did not see ECDSA by RSA cross-signed intermediate and should have")
}
