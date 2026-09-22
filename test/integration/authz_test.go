//go:build integration

package integration

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eggsampler/acme/v3"

	"github.com/letsencrypt/boulder/test"
)

const (
	// validAuthorizationLifetime is the expected valid authorization lifetime. It
	// should match the value in the RA config's "authorizationLifetimeDays"
	// configuration field.
	validAuthorizationLifetime = 30
)

// TestValidAuthzExpires checks that a valid authorization has the expected
// expires time.
func TestValidAuthzExpires(t *testing.T) {
	t.Parallel()
	c, err := makeClient()
	test.AssertNotError(t, err, "makeClient failed")

	// Issue for a random domain
	idents := []acme.Identifier{{Type: "dns", Value: random_domain()}}
	result, err := authAndIssue(c, nil, idents, true, "")
	// There should be no error
	test.AssertNotError(t, err, "authAndIssue failed")
	// The order should be valid
	test.AssertEquals(t, result.Order.Status, "valid")
	// There should be one authorization URL
	test.AssertEquals(t, len(result.Order.Authorizations), 1)

	// Fetching the authz by URL shouldn't fail
	authzURL := result.Order.Authorizations[0]
	authzOb, err := c.FetchAuthorization(c.Account, authzURL)
	test.AssertNotError(t, err, "FetchAuthorization failed")

	// The authz should be valid and for the correct identifier
	test.AssertEquals(t, authzOb.Status, "valid")
	test.AssertEquals(t, authzOb.Identifier.Type, idents[0].Type)
	test.AssertEquals(t, authzOb.Identifier.Value, idents[0].Value)

	// The authz should have the expected expiry date, plus or minus a minute
	expectedExpiresMin := time.Now().AddDate(0, 0, validAuthorizationLifetime).Add(-time.Minute)
	expectedExpiresMax := expectedExpiresMin.Add(2 * time.Minute)
	actualExpires := authzOb.Expires
	if actualExpires.Before(expectedExpiresMin) || actualExpires.After(expectedExpiresMax) {
		t.Errorf("Wrong expiry. Got %s, expected it to be between %s and %s",
			actualExpires, expectedExpiresMin, expectedExpiresMax)
	}
}

func TestParallelValidationConflict(t *testing.T) {
	t.Parallel()

	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		t.Skip("TestParallelValidationConflict requires config-next")
	}

	c, err := makeClient()
	if err != nil {
		t.Fatalf("making client: %s", err)
	}

	name := random_domain()
	order, err := c.NewOrder(c.Account, []acme.Identifier{{Type: "dns", Value: name}})
	if err != nil {
		t.Fatalf("making order: %s", err)
	}

	authz, err := c.FetchAuthorization(c.Account, order.Authorizations[0])
	if err != nil {
		t.Fatalf("fetching authz: %s", err)
	}

	chall, ok := authz.ChallengeMap[acme.ChallengeTypeDNS01]
	if !ok {
		t.Fatalf("authz doesn't have dns-01 challenge")
	}

	// Setting up chall-test-srv to have an actual response isn't strictly
	// necessary, but it makes the success/failure difference between the attempts
	// below more obvious.
	_, err = testSrvClient.AddDNS01Response(name, chall.KeyAuthorization)
	if err != nil {
		t.Fatalf("prepping chall-test-srv: %s", err)
	}
	t.Cleanup(func() {
		testSrvClient.RemoveDNS01Response(chall.Token)
	})

	// Kick off two validations in parallel.
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range 2 {
		wg.Go(func() {
			_, err := c.UpdateChallenge(c.Account, chall)
			errs[i] = err
		})
	}
	wg.Wait()

	// Make sure we got one error and one success.
	if errs[0] == nil && errs[1] == nil {
		t.Error("parallel UpdateChallenge both succeeded, but want one failure")
	} else if errs[0] != nil && errs[1] != nil {
		t.Errorf("parallel UpdateChallenge both failed (%q and %q), but want one success", errs[0], errs[1])
	}

	// Make sure the one error is of type "conflict"
	err = errs[0]
	if err == nil {
		err = errs[1]
	}
	if !strings.Contains(err.Error(), "urn:ietf:params:acme:error:conflict") {
		t.Errorf("parallel UpdateChallenge = %q, but want 'conflict'", err)
	}
}
