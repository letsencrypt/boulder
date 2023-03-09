//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestCommonName(t *testing.T) {
	t.Parallel()

	// Create an account.
	os.Setenv("DIRECTORY", "http://boulder.service.consul:4001/directory")
	client, err := makeClient("mailto:example@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")

	// Create a private key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "creating random cert key")

	// Put together some names.
	cn := random_domain()
	san1 := random_domain()
	san2 := random_domain()

	// Issue a cert. authAndIssue includes the 0th name as the CN by default.
	ir, err := authAndIssue(client, key, []string{cn, san1, san2})
	test.AssertNotError(t, err, "failed to issue test cert")
	cert := ir.certs[0]

	// Ensure that the CN is incorporated into the SANs.
	test.AssertSliceContains(t, cert.DNSNames, cn)
	test.AssertSliceContains(t, cert.DNSNames, san1)
	test.AssertSliceContains(t, cert.DNSNames, san2)

	// Ensure that the CN is (or is not) set, per the SetCommonName flag.
	if strings.Contains(os.Getenv("BOULDER_CONFIG_DIR"), "test/config-next") {
		// In config-next, the SetCommonName flag is false.
		test.AssertEquals(t, cert.Subject.CommonName, "")
	} else {
		// In config, the SetCommonName flag is true.
		test.AssertEquals(t, cert.Subject.CommonName, cn)
	}
}
