//go:build integration

package integration

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eggsampler/acme/v3"
)

func TestDNSPersist01HappyPath(t *testing.T) {
	t.Parallel()

	if os.Getenv("BOULDER_CONFIG_DIR") == "test/config" {
		t.Skip("Test requires dns-persist-01 to be enabled")
	}

	domain := random_domain()
	c, err := makeClient()
	if err != nil {
		t.Fatalf("creating client: %s", err)
	}

	idents := []acme.Identifier{{Type: "dns", Value: domain}}

	order, err := c.Client.NewOrder(c.Account, idents)
	if err != nil {
		t.Fatalf("creating new order: %s", err)
	}

	authzURL := order.Authorizations[0]
	auth, err := c.Client.FetchAuthorization(c.Account, authzURL)
	if err != nil {
		t.Fatalf("fetching authorization: %s", err)
	}

	chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNSPersist01]
	if !ok {
		t.Fatal("dns-persist-01 challenge not offered by server")
	}

	if len(chal.IssuerDomainNames) == 0 {
		t.Fatal("dns-persist-01 challenge missing issuer-domain-names")
	}

	record := fmt.Sprintf("%s;accounturi=%s", chal.IssuerDomainNames[0], c.Account.URL)
	_, err = testSrvClient.AddDNSPersist01Response(domain, record)
	if err != nil {
		t.Fatalf("adding DNS response: %s", err)
	}
	t.Cleanup(func() {
		_, err := testSrvClient.RemoveDNSPersist01Response(domain)
		if err != nil {
			t.Fatal(err)
		}
	})

	chal, err = c.Client.UpdateChallenge(c.Account, chal)
	if err != nil {
		t.Fatalf("updating challenge: %s", err)
	}

	auth, err = c.Client.FetchAuthorization(c.Account, authzURL)
	if err != nil {
		t.Fatalf("fetching authorization after challenge update: %s", err)
	}

	if auth.Status != "valid" {
		t.Fatalf("expected authorization status to be 'valid', got '%s'", auth.Status)
	}
}

func TestDNSPersist01WrongAccountURI(t *testing.T) {
	t.Parallel()

	if os.Getenv("BOULDER_CONFIG_DIR") == "test/config" {
		t.Skip("Test requires dns-persist-01 to be enabled")
	}

	domain := random_domain()
	c, err := makeClient()
	if err != nil {
		t.Fatalf("creating client: %s", err)
	}

	idents := []acme.Identifier{{Type: "dns", Value: domain}}

	order, err := c.Client.NewOrder(c.Account, idents)
	if err != nil {
		t.Fatalf("creating new order: %s", err)
	}

	authzURL := order.Authorizations[0]
	auth, err := c.Client.FetchAuthorization(c.Account, authzURL)
	if err != nil {
		t.Fatalf("fetching authorization: %s", err)
	}

	chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNSPersist01]
	if !ok {
		t.Fatal("dns-persist-01 challenge not offered by server")
	}

	issuer := chal.IssuerDomainNames[0]
	record := fmt.Sprintf("%s;accounturi=https://wrong.example/acct/999", issuer)
	_, err = testSrvClient.AddDNSPersist01Response(domain, record)
	if err != nil {
		t.Fatalf("adding DNS response: %s", err)
	}
	t.Cleanup(func() {
		_, err := testSrvClient.RemoveDNSPersist01Response(domain)
		if err != nil {
			t.Fatal(err)
		}
	})

	_, err = c.Client.UpdateChallenge(c.Account, chal)
	if err == nil {
		t.Fatal("updating challenge: expected error, got nil")
	}
	prob, ok := err.(acme.Problem)
	if !ok {
		t.Fatalf("updating challenge: expected acme.Problem error, got %T", err)
	}
	if prob.Type != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("updating challenge: expected unauthorized error, got %s", prob.Type)
	}
	if !strings.Contains(prob.Detail, "accounturi mismatch") {
		t.Fatalf("updating challenge: expected accounturi mismatch error, got %s", prob.Detail)
	}
}

func TestDNSPersist01WithoutSolvingChallenge(t *testing.T) {
	t.Parallel()

	if os.Getenv("BOULDER_CONFIG_DIR") == "test/config" {
		t.Skip("Test requires dns-persist-01 to be enabled")
	}

	domain := random_domain()
	c, err := makeClient()
	if err != nil {
		t.Fatalf("creating client: %s", err)
	}

	idents := []acme.Identifier{{Type: "dns", Value: domain}}

	order, err := c.Client.NewOrder(c.Account, idents)
	if err != nil {
		t.Fatalf("creating new order: %s", err)
	}

	authzURL := order.Authorizations[0]
	auth, err := c.Client.FetchAuthorization(c.Account, authzURL)
	if err != nil {
		t.Fatalf("fetching authorization: %s", err)
	}

	chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNSPersist01]
	if !ok {
		t.Fatal("dns-persist-01 challenge not offered by server")
	}

	_, err = c.Client.UpdateChallenge(c.Account, chal)
	if err == nil {
		t.Fatal("updating challenge: expected error, got nil")
	}
	prob, ok := err.(acme.Problem)
	if !ok {
		t.Fatalf("updating challenge: expected acme.Problem error, got %T", err)
	}
	if prob.Type != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("updating challenge: expected unauthorized error, got %s", prob.Type)
	}
	if !strings.Contains(prob.Detail, "No TXT record found") {
		t.Fatalf("updating challenge: expected No TXT record found error, got %s", prob.Detail)
	}
}

func TestDNSPersist01WildcardDomain(t *testing.T) {
	t.Parallel()

	if os.Getenv("BOULDER_CONFIG_DIR") == "test/config" {
		t.Skip("Test requires dns-persist-01 to be enabled")
	}

	domain := random_domain()
	wildcardDomain := fmt.Sprintf("*.%s", domain)

	c, err := makeClient()
	if err != nil {
		t.Fatalf("creating client: %s", err)
	}

	idents := []acme.Identifier{{Type: "dns", Value: wildcardDomain}}

	order, err := c.Client.NewOrder(c.Account, idents)
	if err != nil {
		t.Fatalf("creating new order: %s", err)
	}

	authzURL := order.Authorizations[0]
	auth, err := c.Client.FetchAuthorization(c.Account, authzURL)
	if err != nil {
		t.Fatalf("fetching authorization: %s", err)
	}

	chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNSPersist01]
	if !ok {
		t.Fatal("dns-persist-01 challenge not offered by server")
	}

	issuer := chal.IssuerDomainNames[0]
	record := fmt.Sprintf("%s;accounturi=%s;policy=wildcard", issuer, c.Account.URL)
	_, err = testSrvClient.AddDNSPersist01Response(domain, record)
	if err != nil {
		t.Fatalf("adding DNS response: %s", err)
	}
	t.Cleanup(func() {
		_, err := testSrvClient.RemoveDNSPersist01Response(domain)
		if err != nil {
			t.Fatal(err)
		}
	})

	chal, err = c.Client.UpdateChallenge(c.Account, chal)
	if err != nil {
		t.Fatalf("updating challenge: %s", err)
	}

	auth, err = c.Client.FetchAuthorization(c.Account, authzURL)
	if err != nil {
		t.Fatalf("fetching authorization after challenge update: %s", err)
	}

	if auth.Status != "valid" {
		t.Fatalf("expected authorization status to be 'valid', got '%s'", auth.Status)
	}
}

func TestDNSPersist01WildcardMissingPolicy(t *testing.T) {
	t.Parallel()

	if os.Getenv("BOULDER_CONFIG_DIR") == "test/config" {
		t.Skip("Test requires dns-persist-01 to be enabled")
	}

	domain := random_domain()
	wildcardDomain := fmt.Sprintf("*.%s", domain)

	c, err := makeClient()
	if err != nil {
		t.Fatalf("creating client: %s", err)
	}

	idents := []acme.Identifier{{Type: "dns", Value: wildcardDomain}}

	order, err := c.Client.NewOrder(c.Account, idents)
	if err != nil {
		t.Fatalf("creating new order: %s", err)
	}

	authzURL := order.Authorizations[0]
	auth, err := c.Client.FetchAuthorization(c.Account, authzURL)
	if err != nil {
		t.Fatalf("fetching authorization: %s", err)
	}

	chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNSPersist01]
	if !ok {
		t.Fatal("dns-persist-01 challenge not offered by server")
	}

	// Omit policy=wildcard, this should fail for a wildcard order.
	issuer := chal.IssuerDomainNames[0]
	record := fmt.Sprintf("%s;accounturi=%s", issuer, c.Account.URL)
	_, err = testSrvClient.AddDNSPersist01Response(domain, record)
	if err != nil {
		t.Fatalf("adding DNS response: %s", err)
	}
	t.Cleanup(func() {
		_, err := testSrvClient.RemoveDNSPersist01Response(domain)
		if err != nil {
			t.Fatal(err)
		}
	})

	_, err = c.Client.UpdateChallenge(c.Account, chal)
	if err == nil {
		t.Fatal("updating challenge: expected error, got nil")
	}
	prob, ok := err.(acme.Problem)
	if !ok {
		t.Fatalf("updating challenge: expected acme.Problem error, got %T", err)
	}
	if prob.Type != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("updating challenge: expected unauthorized error, got %s", prob.Type)
	}
	if !strings.Contains(prob.Detail, "policy mismatch") {
		t.Fatalf("updating challenge: expected policy mismatch error, got %s", prob.Detail)
	}
}

func TestDNSPersist01MissingAccountURI(t *testing.T) {
	t.Parallel()

	if os.Getenv("BOULDER_CONFIG_DIR") == "test/config" {
		t.Skip("Test requires dns-persist-01 to be enabled")
	}

	domain := random_domain()
	c, err := makeClient()
	if err != nil {
		t.Fatalf("creating client: %s", err)
	}

	idents := []acme.Identifier{{Type: "dns", Value: domain}}

	order, err := c.Client.NewOrder(c.Account, idents)
	if err != nil {
		t.Fatalf("creating new order: %s", err)
	}

	authzURL := order.Authorizations[0]
	auth, err := c.Client.FetchAuthorization(c.Account, authzURL)
	if err != nil {
		t.Fatalf("fetching authorization: %s", err)
	}

	chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNSPersist01]
	if !ok {
		t.Fatal("dns-persist-01 challenge not offered by server")
	}

	// Record with matching issuer but no accounturi parameter.
	issuer := chal.IssuerDomainNames[0]
	record := fmt.Sprintf("%s;policy=wildcard", issuer)
	_, err = testSrvClient.AddDNSPersist01Response(domain, record)
	if err != nil {
		t.Fatalf("adding DNS response: %s", err)
	}
	t.Cleanup(func() {
		_, err := testSrvClient.RemoveDNSPersist01Response(domain)
		if err != nil {
			t.Fatal(err)
		}
	})

	_, err = c.Client.UpdateChallenge(c.Account, chal)
	if err == nil {
		t.Fatal("updating challenge: expected error, got nil")
	}
	prob, ok := err.(acme.Problem)
	if !ok {
		t.Fatalf("updating challenge: expected acme.Problem error, got %T", err)
	}
	if prob.Type != "urn:ietf:params:acme:error:malformed" {
		t.Fatalf("updating challenge: expected malformed error, got %s", prob.Type)
	}
	if !strings.Contains(prob.Detail, "missing mandatory accountURI") {
		t.Fatalf("updating challenge: expected missing accountURI error, got %s", prob.Detail)
	}
}

func TestDNSPersist01WrongIssuer(t *testing.T) {
	t.Parallel()

	if os.Getenv("BOULDER_CONFIG_DIR") == "test/config" {
		t.Skip("Test requires dns-persist-01 to be enabled")
	}

	domain := random_domain()
	c, err := makeClient()
	if err != nil {
		t.Fatalf("creating client: %s", err)
	}

	idents := []acme.Identifier{{Type: "dns", Value: domain}}

	order, err := c.Client.NewOrder(c.Account, idents)
	if err != nil {
		t.Fatalf("creating new order: %s", err)
	}

	authzURL := order.Authorizations[0]
	auth, err := c.Client.FetchAuthorization(c.Account, authzURL)
	if err != nil {
		t.Fatalf("fetching authorization: %s", err)
	}

	chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNSPersist01]
	if !ok {
		t.Fatal("dns-persist-01 challenge not offered by server")
	}
	_ = chal

	// Record with a non-matching issuer-domain-name.
	record := fmt.Sprintf("wrong-issuer.example;accounturi=%s", c.Account.URL)
	_, err = testSrvClient.AddDNSPersist01Response(domain, record)
	if err != nil {
		t.Fatalf("adding DNS response: %s", err)
	}
	t.Cleanup(func() {
		_, err := testSrvClient.RemoveDNSPersist01Response(domain)
		if err != nil {
			t.Fatal(err)
		}
	})

	_, err = c.Client.UpdateChallenge(c.Account, chal)
	if err == nil {
		t.Fatal("updating challenge: expected error, got nil")
	}
	prob, ok := err.(acme.Problem)
	if !ok {
		t.Fatalf("updating challenge: expected acme.Problem error, got %T", err)
	}
	if prob.Type != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("updating challenge: expected unauthorized error, got %s", prob.Type)
	}
	if !strings.Contains(prob.Detail, "No valid TXT record found") {
		t.Fatalf("updating challenge: expected No valid TXT record found error, got %s", prob.Detail)
	}
}

func TestDNSPersist01NoAuthorizationReuse(t *testing.T) {
	t.Parallel()

	if os.Getenv("BOULDER_CONFIG_DIR") == "test/config" {
		t.Skip("Test requires dns-persist-01 to be enabled")
	}

	domain := random_domain()

	c, err := makeClient()
	if err != nil {
		t.Fatalf("creating client: %s", err)
	}

	idents := []acme.Identifier{{Type: "dns", Value: domain}}

	// First order: complete dns-persist-01 challenge.
	order1, err := c.Client.NewOrder(c.Account, idents)
	if err != nil {
		t.Fatalf("creating first order: %s", err)
	}

	authzURL1 := order1.Authorizations[0]
	auth1, err := c.Client.FetchAuthorization(c.Account, authzURL1)
	if err != nil {
		t.Fatalf("fetching first authorization: %s", err)
	}

	chal, ok := auth1.ChallengeMap[acme.ChallengeTypeDNSPersist01]
	if !ok {
		t.Fatal("dns-persist-01 challenge not offered by server")
	}

	issuer := chal.IssuerDomainNames[0]
	record := fmt.Sprintf("%s;accounturi=%s", issuer, c.Account.URL)
	_, err = testSrvClient.AddDNSPersist01Response(domain, record)
	if err != nil {
		t.Fatalf("adding DNS response: %s", err)
	}
	t.Cleanup(func() {
		_, err := testSrvClient.RemoveDNSPersist01Response(domain)
		if err != nil {
			t.Fatal(err)
		}
	})

	chal, err = c.Client.UpdateChallenge(c.Account, chal)
	if err != nil {
		t.Fatalf("updating challenge: %s", err)
	}

	auth1, err = c.Client.FetchAuthorization(c.Account, authzURL1)
	if err != nil {
		t.Fatalf("fetching first authorization after challenge update: %s", err)
	}

	if auth1.Status != "valid" {
		t.Fatalf("expected first authorization status to be 'valid', got '%s'", auth1.Status)
	}

	// Finalize the first order.
	csr, err := makeCSR(nil, idents, false)
	if err != nil {
		t.Fatalf("making csr: %s", err)
	}
	_, err = c.Client.FinalizeOrder(c.Account, order1, csr)
	if err != nil {
		t.Fatalf("finalizing first order: %s", err)
	}

	// Second order: Boulder should NOT reuse the existing dns-persist-01 authorization.
	order2, err := c.Client.NewOrder(c.Account, idents)
	if err != nil {
		t.Fatalf("creating second order: %s", err)
	}

	authzURL2 := order2.Authorizations[0]
	if authzURL1 == authzURL2 {
		t.Errorf("expected different authorization URLs (no reuse), got same: %s", authzURL1)
	}

	auth2, err := c.Client.FetchAuthorization(c.Account, authzURL2)
	if err != nil {
		t.Fatalf("fetching second authorization: %s", err)
	}

	if auth2.Status != "pending" {
		t.Errorf("expected second authorization status to be 'pending', got '%s'", auth2.Status)
	}
}

func TestDNSPersist01PersistUntilFuture(t *testing.T) {
	t.Parallel()

	if os.Getenv("BOULDER_CONFIG_DIR") == "test/config" {
		t.Skip("Test requires dns-persist-01 to be enabled")
	}

	domain := random_domain()
	c, err := makeClient()
	if err != nil {
		t.Fatalf("creating client: %s", err)
	}

	idents := []acme.Identifier{{Type: "dns", Value: domain}}

	order, err := c.Client.NewOrder(c.Account, idents)
	if err != nil {
		t.Fatalf("creating new order: %s", err)
	}

	authzURL := order.Authorizations[0]
	auth, err := c.Client.FetchAuthorization(c.Account, authzURL)
	if err != nil {
		t.Fatalf("fetching authorization: %s", err)
	}

	chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNSPersist01]
	if !ok {
		t.Fatal("dns-persist-01 challenge not offered by server")
	}

	// Set persistuntil to 1 hour in the future; validation should succeed.
	futureTS := time.Now().Add(time.Hour).Unix()
	issuer := chal.IssuerDomainNames[0]
	record := fmt.Sprintf("%s;accounturi=%s;persistuntil=%d", issuer, c.Account.URL, futureTS)
	_, err = testSrvClient.AddDNSPersist01Response(domain, record)
	if err != nil {
		t.Fatalf("adding DNS response: %s", err)
	}
	t.Cleanup(func() {
		_, err := testSrvClient.RemoveDNSPersist01Response(domain)
		if err != nil {
			t.Fatal(err)
		}
	})

	chal, err = c.Client.UpdateChallenge(c.Account, chal)
	if err != nil {
		t.Fatalf("updating challenge: %s", err)
	}

	auth, err = c.Client.FetchAuthorization(c.Account, authzURL)
	if err != nil {
		t.Fatalf("fetching authorization after challenge update: %s", err)
	}

	if auth.Status != "valid" {
		t.Fatalf("expected authorization status to be 'valid', got '%s'", auth.Status)
	}
}

func TestDNSPersist01PersistUntilPast(t *testing.T) {
	t.Parallel()

	if os.Getenv("BOULDER_CONFIG_DIR") == "test/config" {
		t.Skip("Test requires dns-persist-01 to be enabled")
	}

	domain := random_domain()
	c, err := makeClient()
	if err != nil {
		t.Fatalf("creating client: %s", err)
	}

	idents := []acme.Identifier{{Type: "dns", Value: domain}}

	order, err := c.Client.NewOrder(c.Account, idents)
	if err != nil {
		t.Fatalf("creating new order: %s", err)
	}

	authzURL := order.Authorizations[0]
	auth, err := c.Client.FetchAuthorization(c.Account, authzURL)
	if err != nil {
		t.Fatalf("fetching authorization: %s", err)
	}

	chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNSPersist01]
	if !ok {
		t.Fatal("dns-persist-01 challenge not offered by server")
	}

	// Set persistuntil to 1 hour in the past; validation should fail.
	pastTS := time.Now().Add(-time.Hour).Unix()
	issuer := chal.IssuerDomainNames[0]
	record := fmt.Sprintf("%s;accounturi=%s;persistuntil=%d", issuer, c.Account.URL, pastTS)
	_, err = testSrvClient.AddDNSPersist01Response(domain, record)
	if err != nil {
		t.Fatalf("adding DNS response: %s", err)
	}
	t.Cleanup(func() {
		_, err := testSrvClient.RemoveDNSPersist01Response(domain)
		if err != nil {
			t.Fatal(err)
		}
	})

	_, err = c.Client.UpdateChallenge(c.Account, chal)
	if err == nil {
		t.Fatal("updating challenge: expected error, got nil")
	}
	prob, ok := err.(acme.Problem)
	if !ok {
		t.Fatalf("updating challenge: expected acme.Problem error, got %T", err)
	}
	if prob.Type != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("updating challenge: expected unauthorized error, got %s", prob.Type)
	}
	if !strings.Contains(prob.Detail, "is after persistUntil") {
		t.Fatalf("updating challenge: expected persistUntil error, got %s", prob.Detail)
	}
}
