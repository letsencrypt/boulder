//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/eggsampler/acme/v3"
)

func TestDNSAccount01HappyPath(t *testing.T) {
	t.Parallel()

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

	chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNSAccount01]
	if !ok {
		t.Skip("DNS-Account-01 is not offered, skipping test")
	}

	_, err = testSrvClient.AddDNSAccount01Response(c.Account.URL, domain, chal.KeyAuthorization)
	if err != nil {
		t.Fatalf("adding DNS response: %s", err)
	}
	t.Cleanup(func() {
		_, _ = testSrvClient.RemoveDNSAccount01Response(c.Account.URL, domain)
	})

	chal, err = c.Client.UpdateChallenge(c.Account, chal)
	if err != nil {
		t.Fatalf("updating challenge: %s", err)
	}

	csrKey, err := makeCSR(nil, idents, true)
	if err != nil {
		t.Fatalf("making CSR: %s", err)
	}

	order, err = c.Client.FinalizeOrder(c.Account, order, csrKey)
	if err != nil {
		t.Fatalf("finalizing order: %s", err)
	}

	certs, err := c.Client.FetchCertificates(c.Account, order.Certificate)
	if err != nil {
		t.Fatalf("fetching certificates: %s", err)
	}

	if len(certs) == 0 {
		t.Fatal("no certificates returned")
	}

	found := false
	for _, name := range certs[0].DNSNames {
		if name == domain {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("certificate doesn't contain domain %s", domain)
	}
}

func TestDNSAccount01WrongTXTRecord(t *testing.T) {
	t.Parallel()

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

	chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNSAccount01]
	if !ok {
		t.Skip("DNS-Account-01 is not offered, skipping test")
	}

	// Add a wrong TXT record
	_, err = testSrvClient.AddDNSAccount01Response(c.Account.URL, domain, "wrong-digest")
	if err != nil {
		t.Fatalf("adding DNS response: %s", err)
	}
	t.Cleanup(func() {
		_, _ = testSrvClient.RemoveDNSAccount01Response(c.Account.URL, domain)
	})

	_, err = c.Client.UpdateChallenge(c.Account, chal)
	if err == nil {
		t.Fatalf("updating challenge: expected error, got nil")
	}
	prob, ok := err.(acme.Problem)
	if !ok {
		t.Fatalf("updating challenge: expected acme.Problem error, got %T", err)
	}
	if prob.Type != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("updating challenge: expected unauthorized error, got %s", prob.Type)
	}
	if !strings.Contains(prob.Detail, "Incorrect TXT record") {
		t.Fatalf("updating challenge: expected Incorrect TXT record error, got %s", prob.Detail)
	}
}

func TestDNSAccount01NoTXTRecord(t *testing.T) {
	t.Parallel()

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

	chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNSAccount01]
	if !ok {
		t.Skip("DNS-Account-01 is not offered, skipping test")
	}

	// Skip adding a TXT record

	_, err = c.Client.UpdateChallenge(c.Account, chal)
	if err == nil {
		t.Fatalf("updating challenge: expected error, got nil")
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

func TestDNSAccount01MultipleTXTRecordsNoneMatch(t *testing.T) {
	t.Parallel()

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

	chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNSAccount01]
	if !ok {
		t.Skip("DNS-Account-01 is not offered, skipping test")
	}

	// Add multiple wrong TXT records
	_, err = testSrvClient.AddDNSAccount01Response(c.Account.URL, domain, "wrong-digest-1")
	if err != nil {
		t.Fatalf("adding DNS response: %s", err)
	}
	_, err = testSrvClient.AddDNSAccount01Response(c.Account.URL, domain, "wrong-digest-2")
	if err != nil {
		t.Fatalf("adding DNS response: %s", err)
	}
	t.Cleanup(func() {
		_, _ = testSrvClient.RemoveDNSAccount01Response(c.Account.URL, domain)
	})

	_, err = c.Client.UpdateChallenge(c.Account, chal)
	if err == nil {
		t.Fatalf("updating challenge: expected error, got nil")
	}
	prob, ok := err.(acme.Problem)
	if !ok {
		t.Fatalf("updating challenge: expected acme.Problem error, got %T", err)
	}
	if prob.Type != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("updating challenge: expected unauthorized error, got %s", prob.Type)
	}
	if !strings.Contains(prob.Detail, "Incorrect TXT record") {
		t.Fatalf("updating challenge: expected Incorrect TXT record error, got %s", prob.Detail)
	}
}

func TestDNSAccount01MultipleTXTRecordsOneMatches(t *testing.T) {
	t.Parallel()

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

	chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNSAccount01]
	if !ok {
		t.Skip("DNS-Account-01 is not offered, skipping test")
	}

	// Add multiple TXT records, one of which is correct
	_, err = testSrvClient.AddDNSAccount01Response(c.Account.URL, domain, "wrong-digest-1")
	if err != nil {
		t.Fatalf("adding DNS response: %s", err)
	}
	_, err = testSrvClient.AddDNSAccount01Response(c.Account.URL, domain, chal.KeyAuthorization)
	if err != nil {
		t.Fatalf("adding DNS response: %s", err)
	}
	_, err = testSrvClient.AddDNSAccount01Response(c.Account.URL, domain, "wrong-digest-2")
	if err != nil {
		t.Fatalf("adding DNS response: %s", err)
	}
	t.Cleanup(func() {
		_, _ = testSrvClient.RemoveDNSAccount01Response(c.Account.URL, domain)
	})

	chal, err = c.Client.UpdateChallenge(c.Account, chal)
	if err != nil {
		t.Fatalf("updating challenge: expected no error, got %s", err)
	}
}

func TestDNSAccount01WildcardDomain(t *testing.T) {
	t.Parallel()

	hostDomain := randomDomain(t)
	wildcardDomain := fmt.Sprintf("*.%s", randomDomain(t))

	c, err := makeClient()
	if err != nil {
		t.Fatalf("creating client: %s", err)
	}

	idents := []acme.Identifier{
		{Type: "dns", Value: hostDomain},
		{Type: "dns", Value: wildcardDomain},
	}

	order, err := c.Client.NewOrder(c.Account, idents)
	if err != nil {
		t.Fatalf("creating new order: %s", err)
	}

	for _, authzURL := range order.Authorizations {
		auth, err := c.Client.FetchAuthorization(c.Account, authzURL)
		if err != nil {
			t.Fatalf("fetching authorization: %s", err)
		}

		isWildcard := strings.HasPrefix(auth.Identifier.Value, "*.")
		domain := auth.Identifier.Value
		if isWildcard {
			domain = strings.TrimPrefix(domain, "*.")
		}

		chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNSAccount01]
		if !ok {
			t.Skip("DNS-Account-01 is not offered, skipping test")
		}

		_, err = testSrvClient.AddDNSAccount01Response(c.Account.URL, domain, chal.KeyAuthorization)
		if err != nil {
			t.Fatalf("adding DNS response: %s", err)
		}
		t.Cleanup(func() {
			_, _ = testSrvClient.RemoveDNSAccount01Response(c.Account.URL, domain)
		})

		chal, err = c.Client.UpdateChallenge(c.Account, chal)
		if err != nil {
			t.Fatalf("updating challenge: %s", err)
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating cert key: %s", err)
	}

	csr, err := makeCSR(key, idents, false)
	if err != nil {
		t.Fatalf("making CSR: %s", err)
	}

	order, err = c.Client.FinalizeOrder(c.Account, order, csr)
	if err != nil {
		t.Fatalf("finalizing order: %s", err)
	}

	certs, err := c.Client.FetchCertificates(c.Account, order.Certificate)
	if err != nil {
		t.Fatalf("fetching certificates: %s", err)
	}

	if len(certs) == 0 {
		t.Fatal("no certificates returned")
	}

	foundHost := false
	foundWildcard := false
	for _, name := range certs[0].DNSNames {
		if name == hostDomain {
			foundHost = true
		}
		if name == wildcardDomain {
			foundWildcard = true
		}
	}

	if !foundHost {
		t.Errorf("certificate doesn't contain host domain %s", hostDomain)
	}
	if !foundWildcard {
		t.Errorf("certificate doesn't contain wildcard domain %s", wildcardDomain)
	}
}

func TestDNSAccount01Metrics(t *testing.T) {
	t.Parallel()

	domain := random_domain()

	c, err := makeClient()
	if err != nil {
		t.Fatalf("creating client: %s", err)
	}

	order, err := c.Client.NewOrder(c.Account, []acme.Identifier{{Type: "dns", Value: domain}})
	if err != nil {
		t.Fatalf("creating new order: %s", err)
	}

	authzURL := order.Authorizations[0]
	auth, err := c.Client.FetchAuthorization(c.Account, authzURL)
	if err != nil {
		t.Fatalf("fetching authorization: %s", err)
	}

	chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNSAccount01]
	if !ok {
		t.Skip("DNS-Account-01 is not offered, skipping test")
	}

	_, err = testSrvClient.AddDNSAccount01Response(c.Account.URL, domain, "incorrect-value")
	if err != nil {
		t.Fatalf("adding DNS response: %s", err)
	}
	t.Cleanup(func() {
		_, _ = testSrvClient.RemoveDNSAccount01Response(c.Account.URL, domain)
	})

	_, err = c.Client.UpdateChallenge(c.Account, chal)
	if err == nil {
		t.Fatal("expected validation to fail, but it succeeded")
	}

	prob, ok := err.(acme.Problem)
	if !ok {
		t.Fatalf("updating challenge: expected acme.Problem error, got %T", err)
	}
	if prob.Type != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("updating challenge: expected unauthorized error, got %s", prob.Type)
	}
	if !strings.Contains(prob.Detail, "Incorrect TXT record") {
		t.Fatalf("updating challenge: expected Incorrect TXT record error, got %s", prob.Detail)
	}

	newOrder, err := c.Client.NewOrder(c.Account, []acme.Identifier{{Type: "dns", Value: domain}})
	if err != nil {
		t.Fatalf("creating new order for successful test: %s", err)
	}

	newAuthzURL := newOrder.Authorizations[0]
	newAuth, err := c.Client.FetchAuthorization(c.Account, newAuthzURL)
	if err != nil {
		t.Fatalf("fetching new authorization: %s", err)
	}

	newChal, ok := newAuth.ChallengeMap[acme.ChallengeTypeDNSAccount01]
	if !ok {
		t.Fatal("DNS-Account-01 challenge not found in new authorization")
	}

	_, err = testSrvClient.AddDNSAccount01Response(c.Account.URL, domain, newChal.KeyAuthorization)
	if err != nil {
		t.Fatalf("adding DNS response for new challenge: %s", err)
	}

	newChal, err = c.Client.UpdateChallenge(c.Account, newChal)
	if err != nil {
		t.Fatalf("updating new challenge: %s", err)
	}

	if newChal.Status != "valid" {
		t.Fatalf("expected new challenge status to be 'valid', got: %s", newChal.Status)
	}
}
