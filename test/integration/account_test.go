//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/eggsampler/acme/v3"

	"github.com/letsencrypt/boulder/core"
)

// TestAccountDeactivate tests that account deactivation works. It does not test
// that we reject requests for other account statuses, because eggsampler/acme
// wisely does not allow us to construct such malformed requests.
func TestAccountDeactivate(t *testing.T) {
	t.Parallel()

	c, err := acme.NewClient("http://boulder.service.consul:4001/directory")
	if err != nil {
		t.Fatalf("failed to connect to acme directory: %s", err)
	}

	acctKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate account key: %s", err)
	}

	account, err := c.NewAccount(acctKey, false, true, "mailto:hello@blackhole.net")
	if err != nil {
		t.Fatalf("failed to create initial account: %s", err)
	}

	got, err := c.DeactivateAccount(account)
	if err != nil {
		t.Errorf("unexpected error while deactivating account: %s", err)
	}

	if got.Status != string(core.StatusDeactivated) {
		t.Errorf("account deactivation should have set status to %q, instead got %q", core.StatusDeactivated, got.Status)
	}

	if len(got.Contact) != 0 {
		t.Errorf("account deactivation should have cleared contacts field, instead got %+v", got.Contact)
	}
}
