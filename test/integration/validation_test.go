//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eggsampler/acme/v3"
	"github.com/miekg/dns"

	"github.com/letsencrypt/boulder/core"
	challtestsrvclient "github.com/letsencrypt/boulder/test/chall-test-srv-client"
	"github.com/letsencrypt/boulder/test/vars"
)

var expectedUserAgents = []string{"boulder", "remoteva-a", "remoteva-b", "remoteva-c", "remoteva-d"}

func collectUserAgentsFromDNSRequests(requests []challtestsrvclient.DNSRequest) []string {
	userAgents := make([]string, len(requests))
	for i, request := range requests {
		userAgents[i] = request.UserAgent
	}
	return userAgents
}

func assertUserAgentsLength(t *testing.T, got []string, checkType string) {
	t.Helper()

	if len(got) != len(expectedUserAgents) {
		t.Errorf("During %s, expected %d User-Agents, got %d", checkType, len(expectedUserAgents), len(got))
	}
}

func assertExpectedUserAgents(t *testing.T, got []string, checkType string) {
	t.Helper()

	for _, ua := range expectedUserAgents {
		if !slices.Contains(got, ua) {
			t.Errorf("During %s, expected User-Agent %q in %s (got %v)", checkType, ua, expectedUserAgents, got)
		}
	}
}

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

	_, err = testSrvClient.AddARecord(domain, []string{"64.112.117.134"})
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
	if len(validationEvents) != len(expectedUserAgents) {
		t.Errorf("expected %d validation events got %d", len(expectedUserAgents), len(validationEvents))
	}

	dnsEvents, err := testSrvClient.DNSRequestHistory(domain)
	if err != nil {
		t.Fatal(err)
	}

	var caaEvents []challtestsrvclient.DNSRequest
	for _, event := range dnsEvents {
		if event.Question.Qtype == dns.TypeCAA {
			caaEvents = append(caaEvents, event)
		}
	}
	assertUserAgentsLength(t, collectUserAgentsFromDNSRequests(caaEvents), "CAA check")
	assertExpectedUserAgents(t, collectUserAgentsFromDNSRequests(caaEvents), "CAA check")
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

	var validationEvents []challtestsrvclient.DNSRequest
	for _, event := range challDomainDNSEvents {
		if event.Question.Qtype == dns.TypeTXT && event.Question.Name == "_acme-challenge."+domain+"." {
			validationEvents = append(validationEvents, event)
		}
	}
	assertUserAgentsLength(t, collectUserAgentsFromDNSRequests(validationEvents), "DNS-01 validation")
	assertExpectedUserAgents(t, collectUserAgentsFromDNSRequests(validationEvents), "DNS-01 validation")

	domainDNSEvents, err := testSrvClient.DNSRequestHistory(domain)
	if err != nil {
		t.Fatal(err)
	}

	var caaEvents []challtestsrvclient.DNSRequest
	for _, event := range domainDNSEvents {
		if event.Question.Qtype == dns.TypeCAA {
			caaEvents = append(caaEvents, event)
		}
	}
	assertUserAgentsLength(t, collectUserAgentsFromDNSRequests(caaEvents), "CAA check")
	assertExpectedUserAgents(t, collectUserAgentsFromDNSRequests(caaEvents), "CAA check")
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

	var validationUAs []string
	for _, event := range validationEvents {
		if event.URL == "/.well-known/acme-challenge/"+chal.Token {
			validationUAs = append(validationUAs, event.UserAgent)
		}
	}
	assertUserAgentsLength(t, validationUAs, "HTTP-01 validation")
	assertExpectedUserAgents(t, validationUAs, "HTTP-01 validation")

	dnsEvents, err := testSrvClient.DNSRequestHistory(domain)
	if err != nil {
		t.Fatal(err)
	}

	var caaEvents []challtestsrvclient.DNSRequest
	for _, event := range dnsEvents {
		if event.Question.Qtype == dns.TypeCAA {
			caaEvents = append(caaEvents, event)
		}
	}

	assertUserAgentsLength(t, collectUserAgentsFromDNSRequests(caaEvents), "CAA check")
	assertExpectedUserAgents(t, collectUserAgentsFromDNSRequests(caaEvents), "CAA check")
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
	db, err := sql.Open("mysql", vars.DBConnSAFullPerms)
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

func TestCAAAccountURI(t *testing.T) {
	t.Parallel()
	client, err := makeClient()
	if err != nil {
		t.Fatalf("creating acme client: %s", err)
	}

	domain := random_domain()
	idents := []acme.Identifier{{Type: "dns", Value: domain}}
	record := fmt.Sprintf("happy-hacker-ca.invalid; accounturi=%s", client.Account.URL)
	_, err = testSrvClient.AddCAAIssue(domain, record)
	if err != nil {
		t.Fatal(err)
	}
	_, err = authAndIssue(client, nil, idents, true, "")
	if err != nil {
		t.Fatalf("authAndIssue: %s", err)
	}

	newClient, err := makeClient()
	if err != nil {
		t.Fatalf("creating acme client: %s", err)
	}

	// New domain to avoid rate limiting; same old CAA record to trigger CAA error.
	domain = random_domain()
	idents = []acme.Identifier{{Type: "dns", Value: domain}}
	_, err = testSrvClient.AddCAAIssue(domain, record)
	if err != nil {
		t.Fatal(err)
	}
	_, err = authAndIssue(newClient, nil, idents, true, "")
	if err == nil {
		t.Errorf("expected error with mismatched CAA account URI, but got success")
	}
	if err != nil && !strings.Contains(err.Error(), "CAA") {
		t.Errorf("expected CAA error with mismatched CAA account URI, but got: %s", err)
	}
}

func TestCAAValidationMethods(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		caa         string
		challType   string
		expectError bool
	}{
		{"dns-01", acme.ChallengeTypeDNS01, false},
		{"dns-01", acme.ChallengeTypeHTTP01, true},
		{"http-01", acme.ChallengeTypeHTTP01, false},
		{"http-01", acme.ChallengeTypeDNS01, true},
		{"dns-01,http-01", acme.ChallengeTypeDNS01, false},
		{"dns-01,http-01", acme.ChallengeTypeHTTP01, false},
	}

	client, err := makeClient()
	if err != nil {
		t.Fatalf("creating acme client: %s", err)
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s-with-caa-allowing-%s", tc.challType, tc.caa), func(t *testing.T) {
			domain := random_domain()
			record := fmt.Sprintf("happy-hacker-ca.invalid; validationmethods=%s", tc.caa)
			_, err = testSrvClient.AddCAAIssue(domain, record)
			if err != nil {
				t.Fatal(err)
			}

			idents := []acme.Identifier{{Type: "dns", Value: domain}}
			order, err := client.Client.NewOrder(client.Account, idents)
			if err != nil {
				t.Fatalf("creating order: %s", err)
			}

			authz, err := client.Client.FetchAuthorization(client.Account, order.Authorizations[0])
			if err != nil {
				t.Fatalf("fetching authorization: %s", err)
			}

			var chal acme.Challenge
			var ok bool
			switch tc.challType {
			case acme.ChallengeTypeDNS01:
				chal, ok = authz.ChallengeMap[acme.ChallengeTypeDNS01]
				if !ok {
					t.Fatalf("no DNS challenge found in %#v", authz)
				}
				_, err = testSrvClient.AddDNS01Response(domain, chal.KeyAuthorization)
				if err != nil {
					t.Fatalf("adding DNS-01 response: %s", err)
				}
			case acme.ChallengeTypeHTTP01:
				chal, ok = authz.ChallengeMap[acme.ChallengeTypeHTTP01]
				if !ok {
					t.Fatalf("no HTTP challenge found in %#v", authz)
				}
				_, err = testSrvClient.AddHTTP01Response(chal.Token, chal.KeyAuthorization)
				if err != nil {
					t.Fatalf("adding HTTP-01 response: %s", err)
				}
			default:
				t.Fatalf("unknown challenge type: %q", tc.challType)
			}

			chal, err = client.Client.UpdateChallenge(client.Account, chal)
			if err != nil {
				if tc.expectError && !strings.Contains(err.Error(), "CAA") {
					t.Errorf("expected validation to fail due to CAA, but got: %s", err)
				} else if !tc.expectError {
					t.Errorf("issuing with challenge type %q and CAA %q failed: %s", tc.challType, tc.caa, err)
				}
			}
			if err == nil && tc.expectError {
				t.Errorf("issuing with challenge type %q and CAA %q succeeded, but should have failed", tc.challType, tc.caa)
			}
		})
	}
}

// assertStoredECHStatus checks the ECH status of the last validation record
// stored for domain's authorization. The challenge server doesn't report ECH
// use and the WFE strips it, so only the primary VA's status is observable.
func assertStoredECHStatus(t *testing.T, domain string, want core.ECHStatus) {
	t.Helper()

	db, err := sql.Open("mysql", vars.DBConnSAFullPerms)
	if err != nil {
		t.Fatalf("sql.Open: %s", err)
	}
	defer db.Close()

	var recordsJSON []byte
	err = db.QueryRow(`SELECT validationRecord FROM authz2 WHERE identifierValue = ?`, domain).Scan(&recordsJSON)
	if err != nil {
		t.Fatalf("reading validation records for %s: %s", domain, err)
	}

	var records []core.ValidationRecord
	err = json.Unmarshal(recordsJSON, &records)
	if err != nil {
		t.Fatalf("unmarshaling validation records for %s: %s", domain, err)
	}
	if len(records) == 0 {
		t.Fatalf("no validation records stored for %s", domain)
	}

	got := records[len(records)-1].ECH
	if got != want {
		t.Errorf("got stored ECH status %q for %s, want %q", got, domain, want)
	}
}

func TestTLSALPN01ECH(t *testing.T) {
	t.Parallel()

	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		t.Skip("ECH is only enabled in config-next")
	}

	echConfigList, err := testSrvClient.ECHConfigList()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name          string
		echConfigList string
		wantECH       core.ECHStatus
	}{
		{
			name:          "accepted",
			echConfigList: echConfigList,
			wantECH:       core.ECHAccepted,
		},
		{
			name:          "malformed config falls back",
			echConfigList: base64.StdEncoding.EncodeToString([]byte{0x00, 0x04, 0xfe, 0x0d, 0x00, 0x00}),
			wantECH:       core.ECHFailed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Do a normal tls-alpn-01 validation against a domain that is serving
			// an ECH config in an HTTPS record.
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

			_, err = testSrvClient.AddARecord(domain, []string{"64.112.117.134"})
			if err != nil {
				t.Fatalf("adding A record: %s", err)
			}
			defer func() {
				_, _ = testSrvClient.RemoveARecord(domain)
			}()

			_, err = testSrvClient.AddHTTPSRecord(domain, "1 . ech="+tc.echConfigList)
			if err != nil {
				t.Fatalf("adding HTTPS record: %s", err)
			}
			defer func() {
				_, _ = testSrvClient.RemoveHTTPSRecords(domain)
			}()

			_, err = testSrvClient.AddTLSALPN01Response(domain, chal.KeyAuthorization)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				_, _ = testSrvClient.RemoveTLSALPN01Response(domain)
			}()

			_, err = client.Client.UpdateChallenge(client.Account, chal)
			if err != nil {
				t.Fatalf("completing TLS-ALPN-01 validation: %s", err)
			}

			// Check that every perspective made a DNS request for HTTPS records.
			dnsEvents, err := testSrvClient.DNSRequestHistory(domain)
			if err != nil {
				t.Fatal(err)
			}
			var httpsEvents []challtestsrvclient.DNSRequest
			for _, event := range dnsEvents {
				if event.Question.Qtype == dns.TypeHTTPS {
					httpsEvents = append(httpsEvents, event)
				}
			}
			assertExpectedUserAgents(t, collectUserAgentsFromDNSRequests(httpsEvents), "HTTPS lookup")

			// Check that every perspective completed one handshake, and that the
			// primary VA used ECH or not based on the test case.
			events, err := testSrvClient.TLSALPN01RequestHistory(domain)
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != len(expectedUserAgents) {
				t.Errorf("got %d TLS-ALPN-01 handshakes for %s, want %d", len(events), domain, len(expectedUserAgents))
			}
			assertStoredECHStatus(t, domain, tc.wantECH)
		})
	}
}

func TestHTTP01RedirectECH(t *testing.T) {
	t.Parallel()

	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		t.Skip("ECH is only enabled in config-next")
	}

	echConfigList, err := testSrvClient.ECHConfigList()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name          string
		echConfigList string
		wantECH       core.ECHStatus
	}{
		{
			name:          "accepted",
			echConfigList: echConfigList,
			wantECH:       core.ECHAccepted,
		},
		{
			name:          "malformed config falls back",
			echConfigList: base64.StdEncoding.EncodeToString([]byte{0x00, 0x04, 0xfe, 0x0d, 0x00, 0x00}),
			wantECH:       core.ECHFailed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Conduct a http-01 validation for a name which 3XX redirects to an https:// URI.
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
				t.Fatalf("no HTTP-01 challenge found in %#v", authz)
			}

			_, err = testSrvClient.AddARecord(domain, []string{"64.112.117.122"})
			if err != nil {
				t.Fatalf("adding A record: %s", err)
			}
			defer func() {
				_, _ = testSrvClient.RemoveARecord(domain)
			}()

			_, err = testSrvClient.AddHTTPSRecord(domain, "1 . ech="+tc.echConfigList)
			if err != nil {
				t.Fatalf("adding HTTPS record: %s", err)
			}
			defer func() {
				_, _ = testSrvClient.RemoveHTTPSRecords(domain)
			}()

			_, err = testSrvClient.AddHTTP01Response(chal.Token, chal.KeyAuthorization)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				_, _ = testSrvClient.RemoveHTTP01Response(chal.Token)
			}()

			path := "/.well-known/acme-challenge/" + chal.Token
			_, err = testSrvClient.AddHTTPRedirect(path, "https://"+domain+path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				_, _ = testSrvClient.RemoveHTTPRedirect(path)
			}()

			_, err = client.Client.UpdateChallenge(client.Account, chal)
			if err != nil {
				t.Fatalf("completing HTTP-01 validation: %s", err)
			}

			// Check that every perspective did an HTTPS DNS lookup.
			dnsEvents, err := testSrvClient.DNSRequestHistory(domain)
			if err != nil {
				t.Fatal(err)
			}
			var httpsDNSEvents []challtestsrvclient.DNSRequest
			for _, event := range dnsEvents {
				if event.Question.Qtype == dns.TypeHTTPS {
					httpsDNSEvents = append(httpsDNSEvents, event)
				}
			}
			assertExpectedUserAgents(t, collectUserAgentsFromDNSRequests(httpsDNSEvents), "HTTPS lookup")

			// Check that every perspective made one https:// request, and that the
			// primary VA used ECH or not based on the test case.
			events, err := testSrvClient.HTTPRequestHistory(domain)
			if err != nil {
				t.Fatal(err)
			}
			var httpsEvents []challtestsrvclient.HTTPRequest
			for _, event := range events {
				if event.HTTPS {
					httpsEvents = append(httpsEvents, event)
				}
			}
			if len(httpsEvents) != len(expectedUserAgents) {
				t.Errorf("got %d HTTPS requests for %s, want %d", len(httpsEvents), domain, len(expectedUserAgents))
			}
			assertStoredECHStatus(t, domain, tc.wantECH)
		})
	}
}
