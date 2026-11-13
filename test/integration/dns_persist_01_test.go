//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eggsampler/acme/v3"
)

// dnsPersist01RecordValues returns an issuer-domain-name and a hashed
// accounturi for the client's account, computed from the directory's "meta"
// object. The domainName is the domain being validated, or "*" for a record
// which is not bound to a domain.
func dnsPersist01RecordValues(t *testing.T, c *client, domainName string) (string, string) {
	t.Helper()

	// TODO: Use the ACME client's directory once eggsampler/acme supports
	// draft-ietf-acme-dns-persist-02 and exposes these "meta" fields.
	resp, err := http.Get("http://boulder.service.consul:4001/directory")
	if err != nil {
		t.Fatalf("fetching directory: %s", err)
	}
	defer resp.Body.Close()

	var directory struct {
		Meta struct {
			AccountHashPrefix string   `json:"accountHashPrefix"`
			IssuerDomainNames []string `json:"issuerDomainNames"`
		} `json:"meta"`
	}
	err = json.NewDecoder(resp.Body).Decode(&directory)
	if err != nil {
		t.Fatalf("parsing directory: %s", err)
	}
	if directory.Meta.AccountHashPrefix == "" {
		t.Fatal("directory meta is missing accountHashPrefix")
	}
	if len(directory.Meta.IssuerDomainNames) == 0 {
		t.Fatal("directory meta is missing issuerDomainNames")
	}

	preimage := append([]byte{byte(len(domainName))}, domainName+c.Account.Thumbprint+c.Account.URL...)
	digest := sha256.Sum256(preimage)
	accountURI := directory.Meta.AccountHashPrefix + "sha-256/" + base64.RawURLEncoding.EncodeToString(digest[:])
	return directory.Meta.IssuerDomainNames[0], accountURI
}

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

	issuer, accountURI := dnsPersist01RecordValues(t, c, domain)

	// TODO: Check chal.IssuerDomainNames instead once eggsampler/acme supports
	// draft-ietf-acme-dns-persist-02. Until then it parses the -01 field name,
	// so fetch the authorization again to check it.
	var rawAuth struct {
		Challenges []struct {
			Type              string   `json:"type"`
			IssuerDomainNames []string `json:"issuerDomainNames"`
		} `json:"challenges"`
	}
	err = c.Client.Fetch(c.Account, authzURL, &rawAuth)
	if err != nil {
		t.Fatalf("fetching raw authorization: %s", err)
	}
	for _, rawChal := range rawAuth.Challenges {
		if rawChal.Type == acme.ChallengeTypeDNSPersist01 && !slices.Contains(rawChal.IssuerDomainNames, issuer) {
			t.Fatalf("dns-persist-01 challenge issuerDomainNames %q does not contain %q", rawChal.IssuerDomainNames, issuer)
		}
	}

	record := fmt.Sprintf("%s;accounturi=%s", issuer, accountURI)
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

	otherClient, err := makeClient()
	if err != nil {
		t.Fatalf("creating other client: %s", err)
	}
	issuer, otherAccountURI := dnsPersist01RecordValues(t, otherClient, domain)
	record := fmt.Sprintf("%s;accounturi=%s", issuer, otherAccountURI)
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

	issuer, accountURI := dnsPersist01RecordValues(t, c, domain)
	record := fmt.Sprintf("%s;accounturi=%s;policy=wildcard", issuer, accountURI)
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
	issuer, accountURI := dnsPersist01RecordValues(t, c, domain)
	record := fmt.Sprintf("%s;accounturi=%s", issuer, accountURI)
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
	issuer, _ := dnsPersist01RecordValues(t, c, domain)
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
	if !strings.Contains(prob.Detail, "missing mandatory accounturi parameter") {
		t.Fatalf("updating challenge: expected missing accounturi error, got %s", prob.Detail)
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
	_, accountURI := dnsPersist01RecordValues(t, c, domain)
	record := fmt.Sprintf("wrong-issuer.example;accounturi=%s", accountURI)
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

	issuer, accountURI := dnsPersist01RecordValues(t, c, domain)
	record := fmt.Sprintf("%s;accounturi=%s", issuer, accountURI)
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
	issuer, accountURI := dnsPersist01RecordValues(t, c, domain)
	record := fmt.Sprintf("%s;accounturi=%s;persistuntil=%d", issuer, accountURI, futureTS)
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
	issuer, accountURI := dnsPersist01RecordValues(t, c, domain)
	record := fmt.Sprintf("%s;accounturi=%s;persistuntil=%d", issuer, accountURI, pastTS)
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

func TestDNSPersist01AccountURL(t *testing.T) {
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

	issuer, _ := dnsPersist01RecordValues(t, c, domain)
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
	if prob.Type != "urn:ietf:params:acme:error:malformed" {
		t.Fatalf("updating challenge: expected malformed error, got %s", prob.Type)
	}
	if !strings.Contains(prob.Detail, "is not of the form") {
		t.Fatalf("updating challenge: expected hashed URI form error, got %s", prob.Detail)
	}
}

func TestDNSPersist01DomainOmittedAccountURI(t *testing.T) {
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

	issuer, accountURI := dnsPersist01RecordValues(t, c, "*")
	record := fmt.Sprintf("%s;accounturi=%s", issuer, accountURI)
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

func TestDNSPersist01PriorAccountKey(t *testing.T) {
	t.Parallel()

	if os.Getenv("BOULDER_CONFIG_DIR") == "test/config" {
		t.Skip("Test requires dns-persist-01 to be enabled")
	}

	domain := random_domain()
	c, err := makeClient()
	if err != nil {
		t.Fatalf("creating client: %s", err)
	}

	issuer, accountURI := dnsPersist01RecordValues(t, c, domain)
	record := fmt.Sprintf("%s;accounturi=%s", issuer, accountURI)
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

	// Roll the account key over twice, so that the record's key is not the
	// most recently replaced one.
	for range 2 {
		newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("creating new account key: %s", err)
		}
		c.Account, err = c.Client.AccountKeyChange(c.Account, newKey)
		if err != nil {
			t.Fatalf("rolling over account key: %s", err)
		}
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
