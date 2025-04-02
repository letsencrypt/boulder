//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/eggsampler/acme/v3"
	"github.com/letsencrypt/boulder/test/vars"
)

func TestCAARechecking(t *testing.T) {
	t.Parallel()

	domain := randomDomain(t)
	idents := []acme.Identifier{{Type: "dns", Value: domain}}

	// Create an order and authorization, and fulfill the associated challenge.
	// This should put the authz into the "valid" state, since CAA checks passed.
	client, err := makeClient()
	if err != nil {
		t.Fatalf("creating acme client: %s", err)
	}

	order, err := client.Client.NewOrder(client.Account, idents)
	if err != nil {
		t.Fatalf("creating order: %s", err)
	}

	authz, err := client.Client.FetchAuthorization(client.Account, order.Authorizations[0])
	if err != nil {
		t.Fatalf("fetching authorization: %s", err)
	}

	chal, ok := authz.ChallengeMap[acme.ChallengeTypeHTTP01]
	if !ok {
		t.Fatalf("no HTTP challenge found in %#v", authz)
	}

	_, err = testSrvClient.AddHTTP01Response(chal.Token, chal.KeyAuthorization)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, err = testSrvClient.RemoveHTTP01Response(chal.Token)
		if err != nil {
			t.Fatal(err)
		}
	}()

	chal, err = client.Client.UpdateChallenge(client.Account, chal)
	if err != nil {
		t.Fatalf("completing HTTP-01 validation: %s", err)
	}

	// Manipulate the database so that it looks like the authz was validated
	// more than 8 hours ago.
	db, err := sql.Open("mysql", vars.DBConnSAIntegrationFullPerms)
	if err != nil {
		t.Fatalf("sql.Open: %s", err)
	}

	_, err = db.Exec(`UPDATE authz2 SET attemptedAt = ? WHERE identifierValue = ?`, time.Now().Add(-24*time.Hour).Format(time.DateTime), domain)
	if err != nil {
		t.Fatalf("updating authz attemptedAt timestamp: %s", err)
	}

	// Change the CAA record to now forbid issuance.
	_, err = testSrvClient.AddCAAIssue(domain, ";")
	if err != nil {
		t.Fatal(err)
	}

	// Try to finalize the order created above. Due to our db manipulation, this
	// should trigger a CAA recheck. And due to our challtestsrv manipulation,
	// that CAA recheck should fail. Therefore the whole finalize should fail.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating cert key: %s", err)
	}

	csr, err := makeCSR(key, idents, false)
	if err != nil {
		t.Fatalf("generating finalize csr: %s", err)
	}

	_, err = client.Client.FinalizeOrder(client.Account, order, csr)
	if err == nil {
		t.Errorf("expected finalize to fail, but got success")
	}
	if !strings.Contains(err.Error(), "CAA") {
		t.Errorf("expected finalize to fail due to CAA, but got: %s", err)
	}
}
