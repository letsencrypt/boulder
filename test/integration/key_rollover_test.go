//go:build integration

package integration

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/eggsampler/acme/v3"
	"github.com/letsencrypt/boulder/test"
)

// TestAccountKeyChange tests that the whole account key rollover process works,
// including between different kinds of keys.
func TestAccountKeyChange(t *testing.T) {
	t.Parallel()

	// These are all five key types supported by our JWK library and GoodKey checker.
	keyTypes := []struct {
		name string
		gen  func() (crypto.Signer, error)
	}{
		{"ECDSA P256", func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }},
		{"ECDSA P384", func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) }},
		{"RSA 2048", func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 2048) }},
		{"RSA 3072", func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 3072) }},
		{"RSA 4096", func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 4096) }},
	}

	// Test every possible combination of old/new key types, including rolling
	// over to the same kind of key as before.
	for _, old := range keyTypes {
		old := old
		for _, new := range keyTypes {
			new := new
			t.Run(fmt.Sprintf("%s to %s", old.name, new.name), func(t *testing.T) {
				t.Parallel()

				c, err := acme.NewClient("http://boulder.service.consul:4001/directory")
				test.AssertNotError(t, err, "creating client")

				origKey, err := old.gen()
				test.AssertNotError(t, err, fmt.Sprintf("creating %s account key", old.name))

				origAcct, err := c.NewAccount(origKey, false, true)
				test.AssertNotError(t, err, "creating account")

				newKey, err := new.gen()
				test.AssertNotError(t, err, fmt.Sprintf("creating %s account key", new.name))

				newAcct, err := c.AccountKeyChange(origAcct, newKey)
				test.AssertNotError(t, err, "rolling over account key")

				test.AssertEquals(t, newAcct.URL, origAcct.URL)
			})
		}
	}
}
