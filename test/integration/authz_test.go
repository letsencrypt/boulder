// +build integration

package integration

import (
	"os"
	"testing"
	"time"

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
	os.Setenv("DIRECTORY", "http://boulder:4001/directory")
	c, err := makeClient()
	test.AssertNotError(t, err, "makeClient failed")

	// Issue for a random domain
	domains := []string{random_domain()}
	result, err := authAndIssue(c, nil, domains)
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
	test.AssertEquals(t, authzOb.Identifier.Value, domains[0])

	// The authz should have the expected expiry date
	expectedExpires := time.Now().AddDate(0, 0, validAuthorizationLifetime).Round(time.Minute)
	actualExpires := authzOb.Expires.Round(time.Minute)
	if !expectedExpires.Equal(actualExpires) {
		t.Errorf("Wrong expiry. Got %q, expected %q", actualExpires, expectedExpires)
	}
}
