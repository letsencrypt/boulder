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

	// TODO(#5554): Check that the contacts have been cleared. We can't do this
	// today because eggsampler/acme unmarshals the WFE's response into the same
	// account object as it used to make the request, and a wholly missing
	// contacts field doesn't overwrite whatever eggsampler was holding in memory.
}
