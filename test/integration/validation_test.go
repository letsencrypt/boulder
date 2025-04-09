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
	"github.com/miekg/dns"
)

func TestMPICTLSALPN01(t *testing.T) {
	t.Parallel()

	client, err := makeClient()
	if err != nil {
		t.Fatalf("creating acme client: %s", err)
	}

	domain := randomDomain(t)

	order, err := client.Client.NewOrder(client.Account, []acme.Identifier{{Type: "dns", Value: domain}})
	if err != nil {
		t.Fatalf("creating order: %s", err)
	}

	authz, err := client.Client.FetchAuthorization(client.Account, order.Authorizations[0])
	if err != nil {
		t.Fatalf("fetching authorization: %s", err)
	}

	chal, ok := authz.ChallengeMap[acme.ChallengeTypeTLSALPN01]
	if !ok {
		t.Fatalf("no TLS-ALPN-01 challenge found in %#v", authz)
	}

	_, err = testSrvClient.AddARecord(domain, []string{"10.88.88.88"})
	if err != nil {
		t.Fatalf("adding A record: %s", err)
	}
	defer func() {
		testSrvClient.RemoveARecord(domain)
	}()

	_, err = testSrvClient.AddTLSALPN01Response(domain, chal.KeyAuthorization)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, err = testSrvClient.RemoveTLSALPN01Response(domain)
		if err != nil {
			t.Fatal(err)
		}
	}()

	chal, err = client.Client.UpdateChallenge(client.Account, chal)
	if err != nil {
		t.Fatalf("completing TLS-ALPN-01 validation: %s", err)
	}

	validationEvents, err := testSrvClient.TLSALPN01RequestHistory(domain)
	if err != nil {
		t.Fatal(err)
	}
	if len(validationEvents) != 4 {
		t.Errorf("expected 4 validation events (VA=1 RVAs=3), got %d", len(validationEvents))
	}

	dnsEvents, err := testSrvClient.DNSRequestHistory(domain)
	if err != nil {
		t.Fatal(err)
	}

	caaCount := 0
	for _, event := range dnsEvents {
		if event.Question.Qtype == dns.TypeCAA {
			caaCount++
		}
	}
	if caaCount != 4 {
		t.Fatalf("expected 4 CAA validation events (VA=1 RVAs=3), got %d", caaCount)
	}
}

func TestMPICDNS01(t *testing.T) {
	t.Parallel()

	client, err := makeClient()
	if err != nil {
		t.Fatalf("creating acme client: %s", err)
	}

	domain := randomDomain(t)

	order, err := client.Client.NewOrder(client.Account, []acme.Identifier{{Type: "dns", Value: domain}})
	if err != nil {
		t.Fatalf("creating order: %s", err)
	}

	authz, err := client.Client.FetchAuthorization(client.Account, order.Authorizations[0])
	if err != nil {
		t.Fatalf("fetching authorization: %s", err)
	}

	chal, ok := authz.ChallengeMap[acme.ChallengeTypeDNS01]
	if !ok {
		t.Fatalf("no DNS challenge found in %#v", authz)
	}

	_, err = testSrvClient.AddDNS01Response(domain, chal.KeyAuthorization)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, err = testSrvClient.RemoveDNS01Response(domain)
		if err != nil {
			t.Fatal(err)
		}
	}()

	chal, err = client.Client.UpdateChallenge(client.Account, chal)
	if err != nil {
		t.Fatalf("completing DNS-01 validation: %s", err)
	}

	challDomainDNSEvents, err := testSrvClient.DNSRequestHistory("_acme-challenge." + domain)
	if err != nil {
		t.Fatal(err)
	}

	validationCount := 0
	for _, event := range challDomainDNSEvents {
		if event.Question.Qtype == dns.TypeTXT && event.Question.Name == "_acme-challenge."+domain+"." {
			validationCount++
		}
	}
	if validationCount != 4 {
		t.Errorf("expected 4 validation events (VA=1 RVAs=3), got %d", validationCount)
	}

	domainDNSEvents, err := testSrvClient.DNSRequestHistory(domain)
	if err != nil {
		t.Fatal(err)
	}

	caaCount := 0
	for _, event := range domainDNSEvents {
		if event.Question.Qtype == dns.TypeCAA {
			caaCount++
		}
	}
	if caaCount != 4 {
		t.Fatalf("expected 4 CAA validation events (VA=1 RVAs=3), got %d", caaCount)
	}
}

func TestMPICHTTP01(t *testing.T) {
	t.Parallel()

	client, err := makeClient()
	if err != nil {
		t.Fatalf("creating acme client: %s", err)
	}

	domain := randomDomain(t)

	order, err := client.Client.NewOrder(client.Account, []acme.Identifier{{Type: "dns", Value: domain}})
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

	validationEvents, err := testSrvClient.HTTPRequestHistory(domain)
	if err != nil {
		t.Fatal(err)
	}

	validationCount := 0
	for _, event := range validationEvents {
		if event.URL == "/.well-known/acme-challenge/"+chal.Token {
			validationCount++
		}
	}
	if validationCount != 4 {
		t.Errorf("expected 4 validation events (VA=1 RVAs=3), got %d", validationCount)
	}

	dnsEvents, err := testSrvClient.DNSRequestHistory(domain)
	if err != nil {
		t.Fatal(err)
	}

	caaCount := 0
	for _, event := range dnsEvents {
		if event.Question.Qtype == dns.TypeCAA {
			caaCount++
		}
	}
	if caaCount != 4 {
		t.Fatalf("expected 4 CAA validation events (VA=1 RVAs=3), got %d", caaCount)
	}
}

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
