package va

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"

	blog "github.com/letsencrypt/boulder/log"
	vapb "github.com/letsencrypt/boulder/va/proto"
)

var caaBrokenDNSClient = errors.New("dnsClient is broken")

// caaBrokenDNS implements the `dns.DNSClient` interface, but always returns
// errors.
type caaBrokenDNS struct{}

func (b caaBrokenDNS) LookupTXT(_ context.Context, hostname string) ([]string, error) {
	return nil, caaBrokenDNSClient
}

func (b caaBrokenDNS) LookupHost(_ context.Context, hostname string) ([]net.IP, error) {
	return nil, caaBrokenDNSClient
}

func (b caaBrokenDNS) LookupCAA(_ context.Context, domain string) ([]*dns.CAA, string, error) {
	return nil, "", caaBrokenDNSClient
}

// caaHijackedDNS implements the `dns.DNSClient` interface with a set of useful
// test answers for CAA queries. It returns alternate CAA records than what
// caaMockDNS returns simulating either a BGP hijack or DNS records that have
// changed while queries were inflight.
type caaHijackedDNS struct{}

func (h caaHijackedDNS) LookupTXT(_ context.Context, hostname string) ([]string, error) {
	return nil, nil
}

func (h caaHijackedDNS) LookupHost(_ context.Context, hostname string) ([]net.IP, error) {
	ip := net.ParseIP("127.0.0.1")
	return []net.IP{ip}, nil
}

func (h caaHijackedDNS) LookupCAA(_ context.Context, domain string) ([]*dns.CAA, string, error) {
	// These records are altered from their caaMockDNS counterparts. Use this to
	// tickle remoteValidationFailures.
	var results []*dns.CAA
	var record dns.CAA
	switch strings.TrimRight(domain, ".") {
	case "present.com", "present.servfail.com":
		record.Tag = "issue"
		record.Value = "www.honestachmed.dyndns.org"
		results = append(results, &record)
	case "unsatisfiable.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; validationmethods=dns-01"
		results = append(results, &record)
	case "satisfiable-wildcard.com":
		record.Tag = "issue"
		record.Value = ";"
		results = append(results, &record)
	}
	var response string
	if len(results) > 0 {
		response = "foo"
	}
	return results, response, nil
}

// caaMockDNS implements the `dns.DNSClient` interface with a set of useful test
// answers for CAA queries.
type caaMockDNS struct{}

func (mock caaMockDNS) LookupTXT(_ context.Context, hostname string) ([]string, error) {
	return nil, nil
}

func (mock caaMockDNS) LookupHost(_ context.Context, hostname string) ([]net.IP, error) {
	ip := net.ParseIP("127.0.0.1")
	return []net.IP{ip}, nil
}

func (mock caaMockDNS) LookupCAA(_ context.Context, domain string) ([]*dns.CAA, string, error) {
	var results []*dns.CAA
	var record dns.CAA
	switch strings.TrimRight(domain, ".") {
	case "caa-timeout.com":
		return nil, "", fmt.Errorf("error")
	case "reserved.com":
		record.Tag = "issue"
		record.Value = "ca.com"
		results = append(results, &record)
	case "mixedcase.com":
		record.Tag = "iSsUe"
		record.Value = "ca.com"
		results = append(results, &record)
	case "critical.com":
		record.Flag = 1
		record.Tag = "issue"
		record.Value = "ca.com"
		results = append(results, &record)
	case "present.com", "present.servfail.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org"
		results = append(results, &record)
	case "com":
		// com has no CAA records.
		return nil, "", nil
	case "gonetld":
		return nil, "", fmt.Errorf("NXDOMAIN")
	case "servfail.com", "servfail.present.com":
		return results, "", fmt.Errorf("SERVFAIL")
	case "multi-crit-present.com":
		record.Flag = 1
		record.Tag = "issue"
		record.Value = "ca.com"
		results = append(results, &record)
		secondRecord := record
		secondRecord.Value = "letsencrypt.org"
		results = append(results, &secondRecord)
	case "unknown-critical.com":
		record.Flag = 128
		record.Tag = "foo"
		record.Value = "bar"
		results = append(results, &record)
	case "unknown-critical2.com":
		record.Flag = 1
		record.Tag = "foo"
		record.Value = "bar"
		results = append(results, &record)
	case "unknown-noncritical.com":
		record.Flag = 0x7E // all bits we don't treat as meaning "critical"
		record.Tag = "foo"
		record.Value = "bar"
		results = append(results, &record)
	case "present-with-parameter.com":
		record.Tag = "issue"
		record.Value = "  letsencrypt.org  ;foo=bar;baz=bar"
		results = append(results, &record)
	case "present-with-invalid-tag.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; a_b=123"
		results = append(results, &record)
	case "present-with-invalid-value.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; ab=1 2 3"
		results = append(results, &record)
	case "present-dns-only.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; validationmethods=dns-01"
		results = append(results, &record)
	case "present-http-only.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; validationmethods=http-01"
		results = append(results, &record)
	case "present-http-or-dns.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; validationmethods=http-01,dns-01"
		results = append(results, &record)
	case "present-dns-only-correct-accounturi.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; accounturi=https://letsencrypt.org/acct/reg/123; validationmethods=dns-01"
		results = append(results, &record)
	case "present-http-only-correct-accounturi.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; accounturi=https://letsencrypt.org/acct/reg/123; validationmethods=http-01"
		results = append(results, &record)
	case "present-http-only-incorrect-accounturi.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; accounturi=https://letsencrypt.org/acct/reg/321; validationmethods=http-01"
		results = append(results, &record)
	case "present-correct-accounturi.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; accounturi=https://letsencrypt.org/acct/reg/123"
		results = append(results, &record)
	case "present-incorrect-accounturi.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; accounturi=https://letsencrypt.org/acct/reg/321"
		results = append(results, &record)
	case "present-multiple-accounturi.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org; accounturi=https://letsencrypt.org/acct/reg/321"
		results = append(results, &record)
		secondRecord := record
		secondRecord.Tag = "issue"
		secondRecord.Value = "letsencrypt.org; accounturi=https://letsencrypt.org/acct/reg/123"
		results = append(results, &secondRecord)
	case "unsatisfiable.com":
		record.Tag = "issue"
		record.Value = ";"
		results = append(results, &record)
	case "unsatisfiable-wildcard.com":
		// Forbidden issuance - issuewild doesn't contain LE
		record.Tag = "issuewild"
		record.Value = ";"
		results = append(results, &record)
	case "unsatisfiable-wildcard-override.com":
		// Forbidden issuance - issue allows LE, issuewild overrides and does not
		record.Tag = "issue"
		record.Value = "letsencrypt.org"
		results = append(results, &record)
		secondRecord := record
		secondRecord.Tag = "issuewild"
		secondRecord.Value = "ca.com"
		results = append(results, &secondRecord)
	case "satisfiable-wildcard-override.com":
		// Ok issuance - issue doesn't allow LE, issuewild overrides and does
		record.Tag = "issue"
		record.Value = "ca.com"
		results = append(results, &record)
		secondRecord := record
		secondRecord.Tag = "issuewild"
		secondRecord.Value = "letsencrypt.org"
		results = append(results, &secondRecord)
	case "satisfiable-multi-wildcard.com":
		// Ok issuance - first issuewild doesn't permit LE but second does
		record.Tag = "issuewild"
		record.Value = "ca.com"
		results = append(results, &record)
		secondRecord := record
		secondRecord.Tag = "issuewild"
		secondRecord.Value = "letsencrypt.org"
		results = append(results, &secondRecord)
	case "satisfiable-wildcard.com":
		// Ok issuance - issuewild allows LE
		record.Tag = "issuewild"
		record.Value = "letsencrypt.org"
		results = append(results, &record)
	}
	var response string
	if len(results) > 0 {
		response = "foo"
	}
	return results, response, nil
}

func TestCAATimeout(t *testing.T) {
	va, _ := setup(nil, 0, "", nil)
	va.dnsClient = caaMockDNS{}

	params := &caaParams{
		accountURIID:     12345,
		validationMethod: core.ChallengeTypeHTTP01,
	}

	err := va.checkCAA(ctx, identifier.DNSIdentifier("caa-timeout.com"), params)
	if err.Type != probs.DNSProblem {
		t.Errorf("Expected timeout error type %s, got %s", probs.DNSProblem, err.Type)
	}

	expected := "error"
	if err.Detail != expected {
		t.Errorf("checkCAA: got %#v, expected %#v", err.Detail, expected)
	}
}

func TestCAAChecking(t *testing.T) {
	testCases := []struct {
		Name    string
		Domain  string
		FoundAt string
		Valid   bool
	}{
		{
			Name:    "Bad (Reserved)",
			Domain:  "reserved.com",
			FoundAt: "reserved.com",
			Valid:   false,
		},
		{
			Name:    "Bad (Reserved, Mixed case Issue)",
			Domain:  "mixedcase.com",
			FoundAt: "mixedcase.com",
			Valid:   false,
		},
		{
			Name:    "Bad (Critical)",
			Domain:  "critical.com",
			FoundAt: "critical.com",
			Valid:   false,
		},
		{
			Name:    "Bad (NX Critical)",
			Domain:  "nx.critical.com",
			FoundAt: "critical.com",
			Valid:   false,
		},
		{
			Name:    "Good (absent)",
			Domain:  "absent.com",
			FoundAt: "",
			Valid:   true,
		},
		{
			Name:    "Good (example.co.uk, absent)",
			Domain:  "example.co.uk",
			FoundAt: "",
			Valid:   true,
		},
		{
			Name:    "Good (present and valid)",
			Domain:  "present.com",
			FoundAt: "present.com",
			Valid:   true,
		},
		{
			Name:    "Good (present on parent)",
			Domain:  "child.present.com",
			FoundAt: "present.com",
			Valid:   true,
		},
		{
			Name:    "Good (present w/ servfail exception?)",
			Domain:  "present.servfail.com",
			FoundAt: "present.servfail.com",
			Valid:   true,
		},
		{
			Name:    "Good (multiple critical, one matching)",
			Domain:  "multi-crit-present.com",
			FoundAt: "multi-crit-present.com",
			Valid:   true,
		},
		{
			Name:    "Bad (unknown critical)",
			Domain:  "unknown-critical.com",
			FoundAt: "unknown-critical.com",
			Valid:   false,
		},
		{
			Name:    "Bad (unknown critical 2)",
			Domain:  "unknown-critical2.com",
			FoundAt: "unknown-critical2.com",
			Valid:   false,
		},
		{
			Name:    "Good (unknown non-critical, no issue/issuewild)",
			Domain:  "unknown-noncritical.com",
			FoundAt: "unknown-noncritical.com",
			Valid:   true,
		},
		{
			Name:    "Good (issue rec with unknown params)",
			Domain:  "present-with-parameter.com",
			FoundAt: "present-with-parameter.com",
			Valid:   true,
		},
		{
			Name:    "Bad (issue rec with invalid tag)",
			Domain:  "present-with-invalid-tag.com",
			FoundAt: "present-with-invalid-tag.com",
			Valid:   false,
		},
		{
			Name:    "Bad (issue rec with invalid value)",
			Domain:  "present-with-invalid-value.com",
			FoundAt: "present-with-invalid-value.com",
			Valid:   false,
		},
		{
			Name:    "Bad (restricts to dns-01, but tested with http-01)",
			Domain:  "present-dns-only.com",
			FoundAt: "present-dns-only.com",
			Valid:   false,
		},
		{
			Name:    "Good (restricts to http-01, tested with http-01)",
			Domain:  "present-http-only.com",
			FoundAt: "present-http-only.com",
			Valid:   true,
		},
		{
			Name:    "Good (restricts to http-01 or dns-01, tested with http-01)",
			Domain:  "present-http-or-dns.com",
			FoundAt: "present-http-or-dns.com",
			Valid:   true,
		},
		{
			Name:    "Good (restricts to accounturi, tested with correct account)",
			Domain:  "present-correct-accounturi.com",
			FoundAt: "present-correct-accounturi.com",
			Valid:   true,
		},
		{
			Name:    "Good (restricts to http-01 and accounturi, tested with correct account)",
			Domain:  "present-http-only-correct-accounturi.com",
			FoundAt: "present-http-only-correct-accounturi.com",
			Valid:   true,
		},
		{
			Name:    "Bad (restricts to dns-01 and accounturi, tested with http-01)",
			Domain:  "present-dns-only-correct-accounturi.com",
			FoundAt: "present-dns-only-correct-accounturi.com",
			Valid:   false,
		},
		{
			Name:    "Bad (restricts to http-01 and accounturi, tested with incorrect account)",
			Domain:  "present-http-only-incorrect-accounturi.com",
			FoundAt: "present-http-only-incorrect-accounturi.com",
			Valid:   false,
		},
		{
			Name:    "Bad (restricts to accounturi, tested with incorrect account)",
			Domain:  "present-incorrect-accounturi.com",
			FoundAt: "present-incorrect-accounturi.com",
			Valid:   false,
		},
		{
			Name:    "Good (restricts to multiple accounturi, tested with a correct account)",
			Domain:  "present-multiple-accounturi.com",
			FoundAt: "present-multiple-accounturi.com",
			Valid:   true,
		},
		{
			Name:    "Bad (unsatisfiable issue record)",
			Domain:  "unsatisfiable.com",
			FoundAt: "unsatisfiable.com",
			Valid:   false,
		},
		{
			Name:    "Bad (unsatisfiable issue, wildcard)",
			Domain:  "*.unsatisfiable.com",
			FoundAt: "unsatisfiable.com",
			Valid:   false,
		},
		{
			Name:    "Bad (unsatisfiable wildcard)",
			Domain:  "*.unsatisfiable-wildcard.com",
			FoundAt: "unsatisfiable-wildcard.com",
			Valid:   false,
		},
		{
			Name:    "Bad (unsatisfiable wildcard override)",
			Domain:  "*.unsatisfiable-wildcard-override.com",
			FoundAt: "unsatisfiable-wildcard-override.com",
			Valid:   false,
		},
		{
			Name:    "Good (satisfiable wildcard)",
			Domain:  "*.satisfiable-wildcard.com",
			FoundAt: "satisfiable-wildcard.com",
			Valid:   true,
		},
		{
			Name:    "Good (multiple issuewild, one satisfiable)",
			Domain:  "*.satisfiable-multi-wildcard.com",
			FoundAt: "satisfiable-multi-wildcard.com",
			Valid:   true,
		},
		{
			Name:    "Good (satisfiable wildcard override)",
			Domain:  "*.satisfiable-wildcard-override.com",
			FoundAt: "satisfiable-wildcard-override.com",
			Valid:   true,
		},
	}

	accountURIID := int64(123)
	method := core.ChallengeTypeHTTP01
	params := &caaParams{accountURIID: accountURIID, validationMethod: method}

	va, _ := setup(nil, 0, "", nil)
	va.dnsClient = caaMockDNS{}
	va.accountURIPrefixes = []string{"https://letsencrypt.org/acct/reg/"}

	for _, caaTest := range testCases {
		mockLog := va.log.(*blog.Mock)
		mockLog.Clear()
		t.Run(caaTest.Name, func(t *testing.T) {
			ident := identifier.DNSIdentifier(caaTest.Domain)
			foundAt, valid, _, err := va.checkCAARecords(ctx, ident, params)
			if err != nil {
				t.Errorf("checkCAARecords error for %s: %s", caaTest.Domain, err)
			}
			if foundAt != caaTest.FoundAt {
				t.Errorf("checkCAARecords presence mismatch for %s: got %q expected %q", caaTest.Domain, foundAt, caaTest.FoundAt)
			}
			if valid != caaTest.Valid {
				t.Errorf("checkCAARecords validity mismatch for %s: got %t expected %t", caaTest.Domain, valid, caaTest.Valid)
			}
		})
	}
}

func TestCAALogging(t *testing.T) {
	va, _ := setup(nil, 0, "", nil)
	va.dnsClient = caaMockDNS{}

	testCases := []struct {
		Name            string
		Domain          string
		AccountURIID    int64
		ChallengeType   core.AcmeChallenge
		ExpectedLogline string
	}{
		{
			Domain:          "reserved.com",
			AccountURIID:    12345,
			ChallengeType:   core.ChallengeTypeHTTP01,
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for reserved.com, [Present: true, Account ID: 12345, Challenge: http-01, Valid for issuance: false, Found at: \"reserved.com\"] Response=\"foo\"",
		},
		{
			Domain:          "reserved.com",
			AccountURIID:    12345,
			ChallengeType:   core.ChallengeTypeDNS01,
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for reserved.com, [Present: true, Account ID: 12345, Challenge: dns-01, Valid for issuance: false, Found at: \"reserved.com\"] Response=\"foo\"",
		},
		{
			Domain:          "mixedcase.com",
			AccountURIID:    12345,
			ChallengeType:   core.ChallengeTypeHTTP01,
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for mixedcase.com, [Present: true, Account ID: 12345, Challenge: http-01, Valid for issuance: false, Found at: \"mixedcase.com\"] Response=\"foo\"",
		},
		{
			Domain:          "critical.com",
			AccountURIID:    12345,
			ChallengeType:   core.ChallengeTypeHTTP01,
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for critical.com, [Present: true, Account ID: 12345, Challenge: http-01, Valid for issuance: false, Found at: \"critical.com\"] Response=\"foo\"",
		},
		{
			Domain:          "present.com",
			AccountURIID:    12345,
			ChallengeType:   core.ChallengeTypeHTTP01,
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for present.com, [Present: true, Account ID: 12345, Challenge: http-01, Valid for issuance: true, Found at: \"present.com\"] Response=\"foo\"",
		},
		{
			Domain:          "not.here.but.still.present.com",
			AccountURIID:    12345,
			ChallengeType:   core.ChallengeTypeHTTP01,
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for not.here.but.still.present.com, [Present: true, Account ID: 12345, Challenge: http-01, Valid for issuance: true, Found at: \"present.com\"] Response=\"foo\"",
		},
		{
			Domain:          "multi-crit-present.com",
			AccountURIID:    12345,
			ChallengeType:   core.ChallengeTypeHTTP01,
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for multi-crit-present.com, [Present: true, Account ID: 12345, Challenge: http-01, Valid for issuance: true, Found at: \"multi-crit-present.com\"] Response=\"foo\"",
		},
		{
			Domain:          "present-with-parameter.com",
			AccountURIID:    12345,
			ChallengeType:   core.ChallengeTypeHTTP01,
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for present-with-parameter.com, [Present: true, Account ID: 12345, Challenge: http-01, Valid for issuance: true, Found at: \"present-with-parameter.com\"] Response=\"foo\"",
		},
		{
			Domain:          "satisfiable-wildcard-override.com",
			AccountURIID:    12345,
			ChallengeType:   core.ChallengeTypeHTTP01,
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for satisfiable-wildcard-override.com, [Present: true, Account ID: 12345, Challenge: http-01, Valid for issuance: false, Found at: \"satisfiable-wildcard-override.com\"] Response=\"foo\"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Domain, func(t *testing.T) {
			mockLog := va.log.(*blog.Mock)
			mockLog.Clear()

			params := &caaParams{
				accountURIID:     tc.AccountURIID,
				validationMethod: tc.ChallengeType,
			}
			_ = va.checkCAA(ctx, identifier.ACMEIdentifier{Type: identifier.DNS, Value: tc.Domain}, params)

			caaLogLines := mockLog.GetAllMatching(`Checked CAA records for`)
			if len(caaLogLines) != 1 {
				t.Errorf("checkCAARecords didn't audit log CAA record info. Instead got:\n%s\n",
					strings.Join(mockLog.GetAllMatching(`.*`), "\n"))
			} else {
				test.AssertEquals(t, caaLogLines[0], tc.ExpectedLogline)
			}
		})
	}
}

// TestIsCAAValidErrMessage tests that an error result from `va.IsCAAValid`
// includes the domain name that was being checked in the failure detail.
func TestIsCAAValidErrMessage(t *testing.T) {
	va, _ := setup(nil, 0, "", nil)
	va.dnsClient = caaMockDNS{}

	// Call IsCAAValid with a domain we know fails with a generic error from the
	// caaMockDNS.
	domain := "caa-timeout.com"
	resp, err := va.IsCAAValid(ctx, &vapb.IsCAAValidRequest{
		Domain:           domain,
		ValidationMethod: string(core.ChallengeTypeHTTP01),
		AccountURIID:     12345,
	})

	// The lookup itself should not return an error
	test.AssertNotError(t, err, "Unexpected error calling IsCAAValidRequest")
	// The result should not be nil
	test.AssertNotNil(t, resp, "Response to IsCAAValidRequest was nil")
	// The result's Problem should not be nil
	test.AssertNotNil(t, resp.Problem, "Response Problem was nil")
	// The result's Problem should be an error message that includes the domain.
	test.AssertEquals(t, resp.Problem.Detail, fmt.Sprintf("While processing CAA for %s: error", domain))
}

// TestIsCAAValidParams tests that the IsCAAValid method rejects any requests
// which do not have the necessary parameters to do CAA Account and Method
// Binding checks.
func TestIsCAAValidParams(t *testing.T) {
	va, _ := setup(nil, 0, "", nil)
	va.dnsClient = caaMockDNS{}

	// Calling IsCAAValid without a ValidationMethod should fail.
	_, err := va.IsCAAValid(ctx, &vapb.IsCAAValidRequest{
		Domain:       "present.com",
		AccountURIID: 12345,
	})
	test.AssertError(t, err, "calling IsCAAValid without a ValidationMethod")

	// Calling IsCAAValid with an invalid ValidationMethod should fail.
	_, err = va.IsCAAValid(ctx, &vapb.IsCAAValidRequest{
		Domain:           "present.com",
		ValidationMethod: "tls-sni-01",
		AccountURIID:     12345,
	})
	test.AssertError(t, err, "calling IsCAAValid with a bad ValidationMethod")

	// Calling IsCAAValid without an AccountURIID should fail.
	_, err = va.IsCAAValid(ctx, &vapb.IsCAAValidRequest{
		Domain:           "present.com",
		ValidationMethod: string(core.ChallengeTypeHTTP01),
	})
	test.AssertError(t, err, "calling IsCAAValid without an AccountURIID")
}

func TestMultiVACAARechecking(t *testing.T) {
	const (
		localUA   = "local01"
		remoteUA1 = "remote01"
		remoteUA2 = "remote02"
		remoteUA3 = "remote03"
		// The remote differential log order is non-deterministic, so let's use
		// the same UA for all applicable RVAs.
		brokenUA   = "broken"
		hijackedUA = "hijacked"
	)
	remoteVA1 := setupRemote(nil, remoteUA1, nil)
	remoteVA2 := setupRemote(nil, remoteUA2, nil)
	remoteVA3 := setupRemote(nil, remoteUA3, nil)

	var bClient bdns.Client
	bClient = caaBrokenDNS{}
	brokenDNSClient := &bClient
	brokenVA1 := setupRemote(nil, brokenUA, brokenDNSClient)
	brokenVA2 := setupRemote(nil, brokenUA, brokenDNSClient)
	brokenVA3 := setupRemote(nil, brokenUA, brokenDNSClient)

	var hClient bdns.Client
	hClient = caaHijackedDNS{}
	hijackedDNSClient := &hClient
	hijackedVA1 := setupRemote(nil, hijackedUA, hijackedDNSClient)
	hijackedVA2 := setupRemote(nil, hijackedUA, hijackedDNSClient)
	hijackedVA3 := setupRemote(nil, hijackedUA, hijackedDNSClient)

	earlyReturn := map[string]bool{
		"EnforceMultiVA":     true,
		"MultiVAFullResults": false,
	}
	noEarlyReturn := map[string]bool{
		"EnforceMultiVA":     true,
		"MultiVAFullResults": true,
	}

	/*
		expectedInternalErrLine := fmt.Sprintf(
			`ERR: \[AUDIT\] Remote VA "brokenVA".IsCAAValidRequest failed: %s`,
			errBrokenRemoteVA.Error())
	*/

	//			localVADNSClientOverride: brokenDNSClient,

	testCases := []struct {
		name                     string
		maxLookupFailures        int
		domains                  string
		remoteVAs                []RemoteVA
		features                 map[string]bool
		overallResult            string
		expectedProb             *probs.ProblemDetails
		expectedDifferentialLog  string
		expectedLog              string
		expectedErr              error
		localVADNSClientOverride *bdns.Client // The test runner will default to caaMockDNS{}
	}{
		{
			name:     "all VAs functional, no CAA records, wait for full results",
			domains:  "com",
			features: noEarlyReturn,
			remoteVAs: []RemoteVA{
				{remoteVA1, remoteUA1},
				{remoteVA2, remoteUA2},
				{remoteVA3, remoteUA3},
			},
		},
		{
			name:     "all VAs functional, no CAA records, dont wait for full results",
			domains:  "com",
			features: earlyReturn,
			remoteVAs: []RemoteVA{
				{remoteVA1, remoteUA1},
				{remoteVA2, remoteUA2},
				{remoteVA3, remoteUA3},
			},
		},
		{
			name:                     "broken localVA, RVAs functional, no CAA records, wait for full results",
			domains:                  "com",
			features:                 noEarlyReturn,
			localVADNSClientOverride: brokenDNSClient,
			expectedProb:             probs.DNS("While processing CAA for com: dnsClient is broken"),
			remoteVAs: []RemoteVA{
				{remoteVA1, remoteUA1},
				{remoteVA2, remoteUA2},
				{remoteVA3, remoteUA3},
			},
		},
		{
			name:                     "broken localVA, RVAs functional, no CAA records, dont wait for full results",
			domains:                  "com",
			features:                 earlyReturn,
			localVADNSClientOverride: brokenDNSClient,
			expectedProb:             probs.DNS("While processing CAA for com: dnsClient is broken"),
			remoteVAs: []RemoteVA{
				{remoteVA1, remoteUA1},
				{remoteVA2, remoteUA2},
				{remoteVA3, remoteUA3},
			},
		},
		{
			name:     "functional localVA, 1 broken RVA, no CAA records, wait for full results",
			domains:  "com",
			features: noEarlyReturn,
			remoteVAs: []RemoteVA{
				{brokenVA1, brokenUA},
				{remoteVA2, remoteUA2},
				{remoteVA3, remoteUA3},
			},
			expectedDifferentialLog: `INFO: remoteVADifferentials JSON={"Domain":"present-dns-only.com","AccountID":1,"ChallengeType":"dns-01","PrimaryResult":null,"RemoteSuccesses":2,"RemoteFailures":[{"VAHostname":"broken","Problem":{"type":"dns","detail":"While processing CAA for present-dns-only.com: dnsClient is broken"}}]}`,
		},
		{
			name:     "functional localVA, 1 broken RVA, no CAA records, dont wait for full results",
			domains:  "com",
			features: earlyReturn,
			remoteVAs: []RemoteVA{
				{brokenVA1, brokenUA},
				{remoteVA2, remoteUA2},
				{remoteVA3, remoteUA3},
			},
		},
		{
			name:     "functional localVA, all broken RVAs, no CAA records, wait for full results",
			domains:  "com",
			features: noEarlyReturn,
			remoteVAs: []RemoteVA{
				{brokenVA1, brokenUA},
				{brokenVA2, brokenUA},
				{brokenVA3, brokenUA},
			},
		},
		{
			name:     "functional localVA, all broken RVAs, no CAA records, dont wait for full results",
			domains:  "com",
			features: earlyReturn,
			remoteVAs: []RemoteVA{
				{brokenVA1, brokenUA},
				{brokenVA2, brokenUA},
				{brokenVA3, brokenUA},
			},
		},
		{
			name:     "all VAs functional, CAA issue type present, wait for full results",
			domains:  "present.com",
			features: noEarlyReturn,
			remoteVAs: []RemoteVA{
				{remoteVA1, remoteUA1},
				{remoteVA2, remoteUA2},
				{remoteVA3, remoteUA3},
			},
		},
		{
			name:     "all VAs functional, CAA issue type present, dont wait for full results",
			domains:  "present.com",
			features: earlyReturn,
			remoteVAs: []RemoteVA{
				{remoteVA1, remoteUA1},
				{remoteVA2, remoteUA2},
				{remoteVA3, remoteUA3},
			},
		},
		/*
			{
				name:          "functional localVA, 1 broken RVA, CAA issue type present, wait for full results",
				domains:       "present.com",
				features:      noEarlyReturn,
				overallResult: "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{brokenVA1, brokenUA},
					{remoteVA2, remoteUA2},
					{remoteVA3, remoteUA3},
				},
			},
			{
				name:          "functional localVA, 1 broken RVA, CAA issue type present, dont wait for full results",
				domains:       "present.com",
				features:      earlyReturn,
				overallResult: "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{brokenVA1, brokenUA},
					{remoteVA2, remoteUA2},
					{remoteVA3, remoteUA3},
				},
			},
		*/
		{
			name:     "functional localVA, all broken RVAs, CAA issue type present, wait for full results",
			domains:  "present.com",
			features: noEarlyReturn,
			remoteVAs: []RemoteVA{
				{brokenVA1, brokenUA},
				{brokenVA2, brokenUA},
				{brokenVA3, brokenUA},
			},
			expectedDifferentialLog: `INFO: remoteVADifferentials JSON={"Domain":"present.com","AccountID":1,"ChallengeType":"dns-01","PrimaryResult":null,"RemoteSuccesses":0,"RemoteFailures":[{"VAHostname":"broken","Problem":{"type":"dns","detail":"While processing CAA for present.com: dnsClient is broken"}},{"VAHostname":"broken","Problem":{"type":"dns","detail":"While processing CAA for present.com: dnsClient is broken"}},{"VAHostname":"broken","Problem":{"type":"dns","detail":"While processing CAA for present.com: dnsClient is broken"}}]}`,
			expectedLog:             `INFO: CAA check failed due to remote failures: identifier=present.com err=dns :: During secondary CAA rechecking: While processing CAA for present.com: dnsClient is broken`,
		},
		/*
			{
				name:          "functional localVA, all broken RVAs, CAA issue type present, dont wait for full results",
				domains:       "present.com",
				features:      earlyReturn,
				overallResult: "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{brokenVA1, brokenUA},
					{brokenVA2, brokenUA},
					{brokenVA3, brokenUA},
				},
				expectedLog: `INFO: CAA check failed due to remote failures: identifier=present.com err=dns :: During secondary CAA rechecking: While processing CAA for present.com: dnsClient is broken`,
			},
			/////////////////////////////////
			{
				// The RVA results are dropped because the localVA lookup determined
				// issuance was forbidden.
				name:          "all VAs functional, CAA issue type forbids issuance, wait for full results",
				domains:       "unsatisfiable.com",
				features:      noEarlyReturn,
				overallResult: "Valid for issuance: false",
				expectedProb:  probs.CAA("While processing CAA for unsatisfiable.com: CAA record for unsatisfiable.com prevents issuance"),
				remoteVAs: []RemoteVA{
					{remoteVA1, remoteUA1},
					{remoteVA2, remoteUA2},
					{remoteVA3, remoteUA3},
				},
			},
			{
				// The RVA results are dropped because the localVA lookup determined
				// issuance was forbidden.
				name:          "all VAs functional, CAA issue type forbids issuance, dont wait for full results",
				domains:       "unsatisfiable.com",
				features:      earlyReturn,
				overallResult: "Valid for issuance: false",
				expectedProb:  probs.CAA("While processing CAA for unsatisfiable.com: CAA record for unsatisfiable.com prevents issuance"),
				remoteVAs: []RemoteVA{
					{remoteVA1, remoteUA1},
					{remoteVA2, remoteUA2},
					{remoteVA3, remoteUA3},
				},
			},
			/////////////////////////////////
			{
				name:          "1 hijacked RVA, CAA issue type present, wait for full results",
				domains:       "present.com",
				features:      noEarlyReturn,
				overallResult: "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{remoteVA1, remoteUA1},
					{remoteVA2, remoteUA2},
					{hijackedVA1, hijackedUA},
				},
				expectedDifferentialLog: `INFO: remoteVADifferentials JSON={"Domain":"present.com","AccountID":1,"ChallengeType":"dns-01","PrimaryResult":null,"RemoteSuccesses":2,"RemoteFailures":[{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for present.com: CAA record for present.com prevents issuance"}}]}`,
			},
			{
				name:          "1 hijacked RVA, CAA issue type present, dont wait for full results",
				domains:       "present.com",
				features:      earlyReturn,
				overallResult: "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{remoteVA1, remoteUA1},
					{remoteVA2, remoteUA2},
					{hijackedVA1, hijackedUA},
				},
				//	expectedLog: `INFO: CAA check failed due to remote failures: identifier=present.com err=caa :: During secondary CAA rechecking: While processing CAA for present.com: CAA record for present.com prevents issuance`,
			},
			{
				name:          "2 hijacked RVAs, CAA issue type present, wait for full results",
				domains:       "present.com",
				features:      noEarlyReturn,
				overallResult: "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{remoteVA1, remoteUA1},
					{hijackedVA1, hijackedUA},
					{hijackedVA2, hijackedUA},
				},
				expectedDifferentialLog: `INFO: remoteVADifferentials JSON={"Domain":"present.com","AccountID":1,"ChallengeType":"dns-01","PrimaryResult":null,"RemoteSuccesses":1,"RemoteFailures":[{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for present.com: CAA record for present.com prevents issuance"}},{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for present.com: CAA record for present.com prevents issuance"}}]}`,
			},
			{
				name:          "2 hijacked RVAs, CAA issue type present, dont wait for full results",
				domains:       "present.com",
				features:      earlyReturn,
				overallResult: "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{remoteVA1, remoteUA1},
					{hijackedVA1, hijackedUA},
					{hijackedVA2, hijackedUA},
				},
				expectedLog: `INFO: CAA check failed due to remote failures: identifier=present.com err=caa :: During secondary CAA rechecking: While processing CAA for present.com: CAA record for present.com prevents issuance`,
			},
			{
				name:          "3 hijacked RVAs, CAA issue type present, wait for full results",
				domains:       "present.com",
				features:      noEarlyReturn,
				overallResult: "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{hijackedVA1, hijackedUA},
					{hijackedVA2, hijackedUA},
					{hijackedVA3, hijackedUA},
				},
				expectedDifferentialLog: `INFO: remoteVADifferentials JSON={"Domain":"present.com","AccountID":1,"ChallengeType":"dns-01","PrimaryResult":null,"RemoteSuccesses":0,"RemoteFailures":[{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for present.com: CAA record for present.com prevents issuance"}},{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for present.com: CAA record for present.com prevents issuance"}},{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for present.com: CAA record for present.com prevents issuance"}}]}`,
			},
			{
				name:          "3 hijacked RVAs, CAA issue type present, dont wait for full results",
				domains:       "present.com",
				features:      earlyReturn,
				overallResult: "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{hijackedVA1, hijackedUA},
					{hijackedVA2, hijackedUA},
					{hijackedVA3, hijackedUA},
				},
				expectedLog: `INFO: CAA check failed due to remote failures: identifier=present.com err=caa :: During secondary CAA rechecking: While processing CAA for present.com: CAA record for present.com prevents issuance`,
			},
			//////////////
			{
				name:          "1 hijacked RVA, CAA issuewild type present, wait for full results",
				domains:       "satisfiable-wildcard.com",
				features:      noEarlyReturn,
				overallResult: "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{remoteVA1, remoteUA1},
					{remoteVA2, remoteUA2},
					{hijackedVA1, hijackedUA},
				},
				expectedDifferentialLog: `INFO: remoteVADifferentials JSON={"Domain":"satisfiable-wildcard.com","AccountID":1,"ChallengeType":"dns-01","PrimaryResult":null,"RemoteSuccesses":2,"RemoteFailures":[{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for satisfiable-wildcard.com: CAA record for satisfiable-wildcard.com prevents issuance"}}]}`,
			},
			{
				name:          "1 hijacked RVA, CAA issuewild type present, dont wait for full results",
				domains:       "satisfiable-wildcard.com",
				features:      earlyReturn,
				overallResult: "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{remoteVA1, remoteUA1},
					{remoteVA2, remoteUA2},
					{hijackedVA1, hijackedUA},
				},
				expectedLog: `INFO: CAA check failed due to remote failures: identifier=satisfiable-wildcard.com err=caa :: During secondary CAA rechecking: While processing CAA for satisfiable-wildcard.com: CAA record for satisfiable-wildcard.com prevents issuance`,
			},
			{
				name:          "2 hijacked RVAs, CAA issuewild type present, wait for full results",
				domains:       "satisfiable-wildcard.com",
				features:      noEarlyReturn,
				overallResult: "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{remoteVA1, remoteUA1},
					{hijackedVA1, hijackedUA},
					{hijackedVA2, hijackedUA},
				},
				expectedDifferentialLog: `INFO: remoteVADifferentials JSON={"Domain":"satisfiable-wildcard.com","AccountID":1,"ChallengeType":"dns-01","PrimaryResult":null,"RemoteSuccesses":1,"RemoteFailures":[{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for satisfiable-wildcard.com: CAA record for satisfiable-wildcard.com prevents issuance"}},{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for satisfiable-wildcard.com: CAA record for satisfiable-wildcard.com prevents issuance"}}]}`,
			},
			{
				name:          "2 hijacked RVAs, CAA issuewild type present, dont wait for full results",
				domains:       "satisfiable-wildcard.com",
				features:      earlyReturn,
				overallResult: "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{remoteVA1, remoteUA1},
					{hijackedVA1, hijackedUA},
					{hijackedVA2, hijackedUA},
				},
				expectedLog: `INFO: CAA check failed due to remote failures: identifier=satisfiable-wildcard.com err=caa :: During secondary CAA rechecking: While processing CAA for satisfiable-wildcard.com: CAA record for satisfiable-wildcard.com prevents issuance`,
			},
		*/
		{
			name:     "3 hijacked RVAs, CAA issuewild type present, wait for full results",
			domains:  "satisfiable-wildcard.com",
			features: noEarlyReturn,
			remoteVAs: []RemoteVA{
				{hijackedVA1, hijackedUA},
				{hijackedVA2, hijackedUA},
				{hijackedVA3, hijackedUA},
			},
			expectedDifferentialLog: `INFO: remoteVADifferentials JSON={"Domain":"satisfiable-wildcard.com","AccountID":1,"ChallengeType":"dns-01","PrimaryResult":null,"RemoteSuccesses":0,"RemoteFailures":[{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for satisfiable-wildcard.com: CAA record for satisfiable-wildcard.com prevents issuance"}},{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for satisfiable-wildcard.com: CAA record for satisfiable-wildcard.com prevents issuance"}},{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for satisfiable-wildcard.com: CAA record for satisfiable-wildcard.com prevents issuance"}}]}`,
			expectedLog:             `INFO: CAA check failed due to remote failures: identifier=satisfiable-wildcard.com err=caa :: During secondary CAA rechecking: While processing CAA for satisfiable-wildcard.com: CAA record for satisfiable-wildcard.com prevents issuance`,
		},
		/*
			{
				name:          "3 hijacked RVAs, CAA issuewild type present, dont wait for full results",
				domains:       "satisfiable-wildcard.com",
				features:      earlyReturn,
				overallResult: "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{hijackedVA1, hijackedUA},
					{hijackedVA2, hijackedUA},
					{hijackedVA3, hijackedUA},
				},
				expectedLog: `INFO: CAA check failed due to remote failures: identifier=satisfiable-wildcard.com err=caa :: During secondary CAA rechecking: While processing CAA for satisfiable-wildcard.com: CAA record for satisfiable-wildcard.com prevents issuance`,
			},
			////////////////////////////////////
			{
				name:              "1 hijacked RVA, CAA issuewild type present, wait for full results, 1 failure allowed",
				domains:           "satisfiable-wildcard.com",
				maxLookupFailures: 1,
				features:          noEarlyReturn,
				overallResult:     "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{remoteVA1, remoteUA1},
					{remoteVA2, remoteUA2},
					{hijackedVA1, hijackedUA},
				},
				expectedDifferentialLog: `INFO: remoteVADifferentials JSON={"Domain":"satisfiable-wildcard.com","AccountID":1,"ChallengeType":"dns-01","PrimaryResult":null,"RemoteSuccesses":2,"RemoteFailures":[{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for satisfiable-wildcard.com: CAA record for satisfiable-wildcard.com prevents issuance"}}]}`,
			},
			{
				name:              "1 hijacked RVA, CAA issuewild type present, dont wait for full results, 1 failure allowed",
				domains:           "satisfiable-wildcard.com",
				maxLookupFailures: 1,
				features:          earlyReturn,
				overallResult:     "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{remoteVA1, remoteUA1},
					{remoteVA2, remoteUA2},
					{hijackedVA1, hijackedUA},
				},
				//	expectedProb: probs.CAA("While processing CAA for satisfiable-wildcard.com: CAA record for satisfiable-wildcard.com prevents issuance"),
			},
			{
				name:              "2 hijacked RVAs, CAA issuewild type present, wait for full results, 1 failure allowed",
				domains:           "satisfiable-wildcard.com",
				maxLookupFailures: 1,
				features:          noEarlyReturn,
				overallResult:     "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{remoteVA1, remoteUA1},
					{hijackedVA1, hijackedUA},
					{hijackedVA2, hijackedUA},
				},
				expectedDifferentialLog: `INFO: remoteVADifferentials JSON={"Domain":"satisfiable-wildcard.com","AccountID":1,"ChallengeType":"dns-01","PrimaryResult":null,"RemoteSuccesses":1,"RemoteFailures":[{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for satisfiable-wildcard.com: CAA record for satisfiable-wildcard.com prevents issuance"}},{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for satisfiable-wildcard.com: CAA record for satisfiable-wildcard.com prevents issuance"}}]}`,
			},
			{
				name:              "2 hijacked RVAs, CAA issuewild type present, dont wait for full results, 1 failure allowed",
				domains:           "satisfiable-wildcard.com",
				maxLookupFailures: 1,
				features:          earlyReturn,
				overallResult:     "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{remoteVA1, remoteUA1},
					{hijackedVA1, hijackedUA},
					{hijackedVA2, hijackedUA},
				},
				expectedLog: `INFO: CAA check failed due to remote failures: identifier=satisfiable-wildcard.com err=caa :: During secondary CAA rechecking: While processing CAA for satisfiable-wildcard.com: CAA record for satisfiable-wildcard.com prevents issuance`,
			},
			{
				name:              "3 hijacked RVAs, CAA issuewild type present, wait for full results, 1 failure allowed",
				domains:           "satisfiable-wildcard.com",
				maxLookupFailures: 1,
				features:          noEarlyReturn,
				overallResult:     "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{hijackedVA1, hijackedUA},
					{hijackedVA2, hijackedUA},
					{hijackedVA3, hijackedUA},
				},
				expectedDifferentialLog: `INFO: remoteVADifferentials JSON={"Domain":"satisfiable-wildcard.com","AccountID":1,"ChallengeType":"dns-01","PrimaryResult":null,"RemoteSuccesses":0,"RemoteFailures":[{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for satisfiable-wildcard.com: CAA record for satisfiable-wildcard.com prevents issuance"}},{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for satisfiable-wildcard.com: CAA record for satisfiable-wildcard.com prevents issuance"}},{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for satisfiable-wildcard.com: CAA record for satisfiable-wildcard.com prevents issuance"}}]}`,
			},
			{
				name:              "3 hijacked RVAs, CAA issuewild type present, dont wait for full results, 1 failure allowed",
				domains:           "satisfiable-wildcard.com",
				maxLookupFailures: 1,
				features:          earlyReturn,
				overallResult:     "Valid for issuance: true",
				remoteVAs: []RemoteVA{
					{hijackedVA1, hijackedUA},
					{hijackedVA2, hijackedUA},
					{hijackedVA3, hijackedUA},
				},
				expectedLog: `INFO: CAA check failed due to remote failures: identifier=satisfiable-wildcard.com err=caa :: During secondary CAA rechecking: While processing CAA for satisfiable-wildcard.com: CAA record for satisfiable-wildcard.com prevents issuance`,
			},
		*/
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			va, mockLog := setup(nil, tc.maxLookupFailures, localUA, tc.remoteVAs)
			defer mockLog.Clear()

			if tc.localVADNSClientOverride == nil {
				va.dnsClient = caaMockDNS{}
			} else {
				va.dnsClient = *tc.localVADNSClientOverride
			}

			if tc.features != nil {
				err := features.Set(tc.features)
				test.AssertNotError(t, err, "Failed to set feature flags")
				defer features.Reset()
			}

			isValidRes, err := va.IsCAAValid(context.TODO(), &vapb.IsCAAValidRequest{
				Domain:           tc.domains,
				ValidationMethod: string(core.ChallengeTypeDNS01),
				AccountURIID:     1,
			})
			test.AssertNotError(t, err, "Should not have errored, but did")
			/*
				test.AssertMetricWithLabelsEquals(t, va.metrics.caaRecheckTime, prometheus.Labels{
					"type":         "dns-01",
					"result":       "success",
					"problem_type": "",
				}, 1)
			*/

			//fmt.Printf("PHIL: expectedProb: %#v\n", isValidRes.Problem)
			if tc.expectedProb != nil {
				fmt.Println("PHIL: got here")
				test.AssertEquals(t, isValidRes.Problem.Detail, tc.expectedProb.Detail)
			}

			for _, line := range mockLog.GetAll() {
				fmt.Println(line)
			}

			if tc.overallResult != "" {
				gotErr := mockLog.ExpectMatch(fmt.Sprintf("%s, Found at:", tc.overallResult))
				test.AssertNotError(t, gotErr, "Could not determine if the CAA recheck was valid for issuance")
			}

			// For the case of MultiVA is enabled, and wait for the full result set.
			gotDifferential := mockLog.GetAllMatching("remoteVADifferentials JSON=.*")
			if tc.expectedDifferentialLog != "" {
				test.AssertEquals(t, len(gotDifferential), 1)
				test.AssertEquals(t, gotDifferential[0], tc.expectedDifferentialLog)
			} else {
				test.AssertEquals(t, len(gotDifferential), 0)
			}

			// For the case of MultiVA is enabled, but do not wait for the full result set.
			gotRemoteFailures := mockLog.GetAllMatching("CAA check failed due to remote failures:")
			if tc.expectedLog != "" {
				test.AssertEquals(t, len(gotRemoteFailures), 1)
				test.AssertEquals(t, gotRemoteFailures[0], tc.expectedLog)
			} else {
				test.AssertEquals(t, len(gotRemoteFailures), 0)
			}
		})
	}
}

func TestCAAFailure(t *testing.T) {
	chall := createChallenge(core.ChallengeTypeHTTP01)
	hs := httpSrv(t, chall.Token)
	defer hs.Close()

	va, _ := setup(hs, 0, "", nil)
	va.dnsClient = caaMockDNS{}

	_, prob := va.validate(ctx, dnsi("reserved.com"), 1, chall)
	if prob == nil {
		t.Fatalf("Expected CAA rejection for reserved.com, got success")
	}
	test.AssertEquals(t, prob.Type, probs.CAAProblem)

	_, prob = va.validate(ctx, dnsi("example.gonetld"), 1, chall)
	if prob == nil {
		t.Fatalf("Expected CAA rejection for gonetld, got success")
	}
	test.AssertEquals(t, prob.Type, probs.DNSProblem)
	test.AssertContains(t, prob.Error(), "NXDOMAIN")
}

func TestFilterCAA(t *testing.T) {
	testCases := []struct {
		name              string
		input             []*dns.CAA
		expectedIssueVals []string
		expectedWildVals  []string
		expectedCU        bool
	}{
		{
			name: "recognized non-critical",
			input: []*dns.CAA{
				{Tag: "issue", Value: "a"},
				{Tag: "issuewild", Value: "b"},
				{Tag: "iodef", Value: "c"},
			},
			expectedIssueVals: []string{"a"},
			expectedWildVals:  []string{"b"},
		},
		{
			name: "recognized critical",
			input: []*dns.CAA{
				{Tag: "issue", Value: "a", Flag: 128},
				{Tag: "issuewild", Value: "b", Flag: 128},
				{Tag: "iodef", Value: "c", Flag: 128},
			},
			expectedIssueVals: []string{"a"},
			expectedWildVals:  []string{"b"},
		},
		{
			name: "unrecognized non-critical",
			input: []*dns.CAA{
				{Tag: "unknown", Flag: 2},
			},
		},
		{
			name: "unrecognized critical",
			input: []*dns.CAA{
				{Tag: "unknown", Flag: 128},
			},
			expectedCU: true,
		},
		{
			name: "unrecognized improper critical",
			input: []*dns.CAA{
				{Tag: "unknown", Flag: 1},
			},
			expectedCU: true,
		},
		{
			name: "unrecognized very improper critical",
			input: []*dns.CAA{
				{Tag: "unknown", Flag: 9},
			},
			expectedCU: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			issue, wild, cu := filterCAA(tc.input)
			for _, tag := range issue {
				test.AssertSliceContains(t, tc.expectedIssueVals, tag.Value)
			}
			for _, tag := range wild {
				test.AssertSliceContains(t, tc.expectedWildVals, tag.Value)
			}
			test.AssertEquals(t, tc.expectedCU, cu)
		})
	}
}

func TestSelectCAA(t *testing.T) {
	expected := dns.CAA{Tag: "issue", Value: "foo"}

	// An empty slice of caaResults should return nil, nil
	r := []caaResult{}
	s, err := selectCAA(r)
	test.Assert(t, s == nil, "set is not nil")
	test.AssertNotError(t, err, "error is not nil")

	// A slice of empty caaResults should return nil, "", nil
	r = []caaResult{
		{"", false, nil, nil, false, "", nil},
		{"", false, nil, nil, false, "", nil},
		{"", false, nil, nil, false, "", nil},
	}
	s, err = selectCAA(r)
	test.Assert(t, s == nil, "set is not nil")
	test.AssertNotError(t, err, "error is not nil")

	// A slice of caaResults containing an error followed by a CAA
	// record should return the error
	r = []caaResult{
		{"foo.com", false, nil, nil, false, "", errors.New("oops")},
		{"com", true, []*dns.CAA{&expected}, nil, false, "foo", nil},
	}
	s, err = selectCAA(r)
	test.Assert(t, s == nil, "set is not nil")
	test.AssertError(t, err, "error is nil")
	test.AssertEquals(t, err.Error(), "oops")

	//  A slice of caaResults containing a good record that precedes an
	//  error, should return that good record, not the error
	r = []caaResult{
		{"foo.com", true, []*dns.CAA{&expected}, nil, false, "foo", nil},
		{"com", false, nil, nil, false, "", errors.New("")},
	}
	s, err = selectCAA(r)
	test.AssertEquals(t, len(s.issue), 1)
	test.Assert(t, s.issue[0] == &expected, "Incorrect record returned")
	test.AssertEquals(t, s.dig, "foo")
	test.Assert(t, err == nil, "error is not nil")

	// A slice of caaResults containing multiple CAA records should
	// return the first non-empty CAA record
	r = []caaResult{
		{"bar.foo.com", false, []*dns.CAA{}, []*dns.CAA{}, false, "", nil},
		{"foo.com", true, []*dns.CAA{&expected}, nil, false, "foo", nil},
		{"com", true, []*dns.CAA{&expected}, nil, false, "bar", nil},
	}
	s, err = selectCAA(r)
	test.AssertEquals(t, len(s.issue), 1)
	test.Assert(t, s.issue[0] == &expected, "Incorrect record returned")
	test.AssertEquals(t, s.dig, "foo")
	test.AssertNotError(t, err, "expect nil error")
}

func TestAccountURIMatches(t *testing.T) {
	tests := []struct {
		name     string
		params   map[string]string
		prefixes []string
		id       int64
		want     bool
	}{
		{
			name:   "empty accounturi",
			params: map[string]string{},
			prefixes: []string{
				"https://acme-v01.api.letsencrypt.org/acme/reg/",
			},
			id:   123456,
			want: true,
		},
		{
			name: "non-uri accounturi",
			params: map[string]string{
				"accounturi": "\\invalid 😎/123456",
			},
			prefixes: []string{
				"\\invalid 😎",
			},
			id:   123456,
			want: false,
		},
		{
			name: "simple match",
			params: map[string]string{
				"accounturi": "https://acme-v01.api.letsencrypt.org/acme/reg/123456",
			},
			prefixes: []string{
				"https://acme-v01.api.letsencrypt.org/acme/reg/",
			},
			id:   123456,
			want: true,
		},
		{
			name: "accountid mismatch",
			params: map[string]string{
				"accounturi": "https://acme-v01.api.letsencrypt.org/acme/reg/123456",
			},
			prefixes: []string{
				"https://acme-v01.api.letsencrypt.org/acme/reg/",
			},
			id:   123457,
			want: false,
		},
		{
			name: "multiple prefixes, match first",
			params: map[string]string{
				"accounturi": "https://acme-staging.api.letsencrypt.org/acme/reg/123456",
			},
			prefixes: []string{
				"https://acme-staging.api.letsencrypt.org/acme/reg/",
				"https://acme-staging-v02.api.letsencrypt.org/acme/acct/",
			},
			id:   123456,
			want: true,
		},
		{
			name: "multiple prefixes, match second",
			params: map[string]string{
				"accounturi": "https://acme-v02.api.letsencrypt.org/acme/acct/123456",
			},
			prefixes: []string{
				"https://acme-v01.api.letsencrypt.org/acme/reg/",
				"https://acme-v02.api.letsencrypt.org/acme/acct/",
			},
			id:   123456,
			want: true,
		},
		{
			name: "multiple prefixes, match none",
			params: map[string]string{
				"accounturi": "https://acme-v02.api.letsencrypt.org/acme/acct/123456",
			},
			prefixes: []string{
				"https://acme-v01.api.letsencrypt.org/acme/acct/",
				"https://acme-v03.api.letsencrypt.org/acme/acct/",
			},
			id:   123456,
			want: false,
		},
		{
			name: "three prefixes",
			params: map[string]string{
				"accounturi": "https://acme-v02.api.letsencrypt.org/acme/acct/123456",
			},
			prefixes: []string{
				"https://acme-v01.api.letsencrypt.org/acme/reg/",
				"https://acme-v02.api.letsencrypt.org/acme/acct/",
				"https://acme-v03.api.letsencrypt.org/acme/acct/",
			},
			id:   123456,
			want: true,
		},
		{
			name: "multiple prefixes, wrong accountid",
			params: map[string]string{
				"accounturi": "https://acme-v02.api.letsencrypt.org/acme/acct/123456",
			},
			prefixes: []string{
				"https://acme-v01.api.letsencrypt.org/acme/reg/",
				"https://acme-v02.api.letsencrypt.org/acme/acct/",
			},
			id:   654321,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := caaAccountURIMatches(tc.params, tc.prefixes, tc.id)
			test.AssertEquals(t, got, tc.want)
		})
	}
}

func TestValidationMethodMatches(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]string
		method core.AcmeChallenge
		want   bool
	}{
		{
			name:   "empty validationmethods",
			params: map[string]string{},
			method: core.ChallengeTypeHTTP01,
			want:   true,
		},
		{
			name: "only comma",
			params: map[string]string{
				"validationmethods": ",",
			},
			method: core.ChallengeTypeHTTP01,
			want:   false,
		},
		{
			name: "malformed method",
			params: map[string]string{
				"validationmethods": "howdy !",
			},
			method: core.ChallengeTypeHTTP01,
			want:   false,
		},
		{
			name: "invalid method",
			params: map[string]string{
				"validationmethods": "tls-sni-01",
			},
			method: core.ChallengeTypeHTTP01,
			want:   false,
		},
		{
			name: "simple match",
			params: map[string]string{
				"validationmethods": "http-01",
			},
			method: core.ChallengeTypeHTTP01,
			want:   true,
		},
		{
			name: "simple mismatch",
			params: map[string]string{
				"validationmethods": "dns-01",
			},
			method: core.ChallengeTypeHTTP01,
			want:   false,
		},
		{
			name: "multiple choices, match first",
			params: map[string]string{
				"validationmethods": "http-01,dns-01",
			},
			method: core.ChallengeTypeHTTP01,
			want:   true,
		},
		{
			name: "multiple choices, match second",
			params: map[string]string{
				"validationmethods": "http-01,dns-01",
			},
			method: core.ChallengeTypeDNS01,
			want:   true,
		},
		{
			name: "multiple choices, match none",
			params: map[string]string{
				"validationmethods": "http-01,dns-01",
			},
			method: core.ChallengeTypeTLSALPN01,
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := caaValidationMethodMatches(tc.params, tc.method)
			test.AssertEquals(t, got, tc.want)
		})
	}
}

func TestExtractIssuerDomainAndParameters(t *testing.T) {
	tests := []struct {
		name            string
		value           string
		wantDomain      string
		wantParameters  map[string]string
		expectErrSubstr string
	}{
		{
			name:            "empty record is valid",
			value:           "",
			wantDomain:      "",
			wantParameters:  map[string]string{},
			expectErrSubstr: "",
		},
		{
			name:            "only semicolon is valid",
			value:           ";",
			wantDomain:      "",
			wantParameters:  map[string]string{},
			expectErrSubstr: "",
		},
		{
			name:            "only semicolon and whitespace is valid",
			value:           " ; ",
			wantDomain:      "",
			wantParameters:  map[string]string{},
			expectErrSubstr: "",
		},
		{
			name:            "only domain is valid",
			value:           "letsencrypt.org",
			wantDomain:      "letsencrypt.org",
			wantParameters:  map[string]string{},
			expectErrSubstr: "",
		},
		{
			name:            "only domain with trailing semicolon is valid",
			value:           "letsencrypt.org;",
			wantDomain:      "letsencrypt.org",
			wantParameters:  map[string]string{},
			expectErrSubstr: "",
		},
		{
			name:            "domain with params and whitespace is valid",
			value:           "  letsencrypt.org	;foo=bar;baz=bar",
			wantDomain:      "letsencrypt.org",
			wantParameters:  map[string]string{"foo": "bar", "baz": "bar"},
			expectErrSubstr: "",
		},
		{
			name:            "domain with params and different whitespace is valid",
			value:           "	letsencrypt.org ;foo=bar;baz=bar",
			wantDomain:      "letsencrypt.org",
			wantParameters:  map[string]string{"foo": "bar", "baz": "bar"},
			expectErrSubstr: "",
		},
		{
			name:            "empty params are valid",
			value:           "letsencrypt.org; foo=; baz =	bar",
			wantDomain:      "letsencrypt.org",
			wantParameters:  map[string]string{"foo": "", "baz": "bar"},
			expectErrSubstr: "",
		},
		{
			name:            "whitespace around params is valid",
			value:           "letsencrypt.org; foo=	; baz =	bar",
			wantDomain:      "letsencrypt.org",
			wantParameters:  map[string]string{"foo": "", "baz": "bar"},
			expectErrSubstr: "",
		},
		{
			name:            "comma-separated param values are valid",
			value:           "letsencrypt.org; foo=b1,b2,b3	; baz =		a=b	",
			wantDomain:      "letsencrypt.org",
			wantParameters:  map[string]string{"foo": "b1,b2,b3", "baz": "a=b"},
			expectErrSubstr: "",
		},
		{
			name:            "spaces in param values are invalid",
			value:           "letsencrypt.org; foo=b1,b2,b3	; baz =		a = b	",
			expectErrSubstr: "value contains disallowed character",
		},
		{
			name:            "spaces in param values are still invalid",
			value:           "letsencrypt.org; foo=b1,b2,b3	; baz=a=	b",
			expectErrSubstr: "value contains disallowed character",
		},
		{
			name:            "param without equals sign is invalid",
			value:           "letsencrypt.org; foo=b1,b2,b3	; baz =		a;b	",
			expectErrSubstr: "parameter not formatted as tag=value",
		},
		{
			name:            "hyphens in param values are valid",
			value:           "letsencrypt.org; 1=2; baz=a-b",
			wantDomain:      "letsencrypt.org",
			wantParameters:  map[string]string{"1": "2", "baz": "a-b"},
			expectErrSubstr: "",
		},
		{
			name:            "underscores in param tags are invalid",
			value:           "letsencrypt.org; a_b=123",
			expectErrSubstr: "tag contains disallowed character",
		},
		{
			name:            "multiple spaces in param values are extra invalid",
			value:           "letsencrypt.org; ab=1 2 3",
			expectErrSubstr: "value contains disallowed character",
		},
		{
			name:            "hyphens in param tags are invalid",
			value:           "letsencrypt.org; 1=2; a-b=c",
			expectErrSubstr: "tag contains disallowed character",
		},
		{
			name:            "high codepoints in params are invalid",
			value:           "letsencrypt.org; foo=a\u2615b",
			expectErrSubstr: "value contains disallowed character",
		},
		{
			name:            "missing semicolons between params are invalid",
			value:           "letsencrypt.org; foo=b1,b2,b3 baz=a",
			expectErrSubstr: "value contains disallowed character",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotDomain, gotParameters, gotErr := parseCAARecord(&dns.CAA{Value: tc.value})

			if tc.expectErrSubstr == "" {
				test.AssertNotError(t, gotErr, "")
			} else {
				test.AssertError(t, gotErr, "")
				test.AssertContains(t, gotErr.Error(), tc.expectErrSubstr)
			}

			if tc.wantDomain != "" {
				test.AssertEquals(t, gotDomain, tc.wantDomain)
			}

			if tc.wantParameters != nil {
				test.AssertDeepEquals(t, gotParameters, tc.wantParameters)
			}
		})
	}
}
