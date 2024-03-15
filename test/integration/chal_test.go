//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"
	"testing"

	"github.com/eggsampler/acme/v3"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/test"
)

func TestDNSAccountChallenge(t *testing.T) {
	t.Parallel()

	// Create an account.
	client, err := makeClient("mailto:example@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")

	// Create one non-wildcard and one wildcard domain.
	hostDomain := random_domain()
	wildDomain := fmt.Sprintf("*.%s", random_domain())

	// Create an order with the domains.
	ids := []acme.Identifier{
		{Type: "dns", Value: hostDomain},
		{Type: "dns", Value: wildDomain},
	}
	order, err := client.Client.NewOrder(client.Account, ids)
	test.AssertNotError(t, err, "failed to create order")

	// Iterate over the authorizations and complete the DNS-ACCOUNT-01 challenges.
	for _, authUrl := range order.Authorizations {
		auth, err := client.Client.FetchAuthorization(client.Account, authUrl)
		test.AssertNotError(t, err, "failed to fetch authorization")

		// Find the DNS-ACCOUNT-01 challenge.
		chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNSAccount01]
		test.Assert(t, ok, fmt.Sprintf("no DNS-ACCOUNT-01 challenge at %s", authUrl))

		// Construct the validation domain name and add to the DNS.
		chalHost := getValidationDomainName(client.Account.URL, auth.Wildcard, auth.Identifier.Value)
		err = addDNSResponse(chalHost, chal.KeyAuthorization)
		test.AssertNotError(t, err, "failed adding DNS-ACCOUNT-01 response")

		// Complete the challenge and remove the DNS entry.
		chal, err = client.Client.UpdateChallenge(client.Account, chal)
		delDNSResponse(chalHost)
		test.AssertNotError(t, err, "failed updating challenge")
	}
}

// Implements acme-scoped-dns-challenges validation domain name construction per:
// "_" || base32(SHA-256(<ACCOUNT_RESOURCE_URL>)[0:10]) || "._acme-" || <SCOPE> || "-challenge"
func getValidationDomainName(accountURL string, wildcard bool, domain string) string {
	scope := core.AuthorizationScopeHost
	if wildcard {
		scope = core.AuthorizationScopeWildcard
	}
	acctHash := sha256.Sum256([]byte(accountURL))
	acctLabel := strings.ToLower(base32.StdEncoding.EncodeToString(acctHash[0:10]))
	chalDomain := fmt.Sprintf("_%s._acme-%s-challenge.%s.", acctLabel, scope, domain)
	return chalDomain
}
