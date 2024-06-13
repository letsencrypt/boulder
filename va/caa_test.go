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
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"

	blog "github.com/letsencrypt/boulder/log"
	vapb "github.com/letsencrypt/boulder/va/proto"
)

// caaMockDNS implements the `dns.DNSClient` interface with a set of useful test
// answers for CAA queries.
type caaMockDNS struct{}

func (mock caaMockDNS) LookupTXT(_ context.Context, hostname string) ([]string, bdns.ResolverAddrs, error) {
	return nil, bdns.ResolverAddrs{"caaMockDNS"}, nil
}

func (mock caaMockDNS) LookupHost(_ context.Context, hostname string) ([]net.IP, bdns.ResolverAddrs, error) {
	ip := net.ParseIP("127.0.0.1")
	return []net.IP{ip}, bdns.ResolverAddrs{"caaMockDNS"}, nil
}

func (mock caaMockDNS) LookupCAA(_ context.Context, domain string) ([]*dns.CAA, string, bdns.ResolverAddrs, error) {
	var results []*dns.CAA
	var record dns.CAA
	switch strings.TrimRight(domain, ".") {
	case "caa-timeout.com":
		return nil, "", bdns.ResolverAddrs{"caaMockDNS"}, fmt.Errorf("error")
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
		return nil, "", bdns.ResolverAddrs{"caaMockDNS"}, nil
	case "gonetld":
		return nil, "", bdns.ResolverAddrs{"caaMockDNS"}, fmt.Errorf("NXDOMAIN")
	case "servfail.com", "servfail.present.com":
		return results, "", bdns.ResolverAddrs{"caaMockDNS"}, fmt.Errorf("SERVFAIL")
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
	return results, response, bdns.ResolverAddrs{"caaMockDNS"}, nil
}

func TestCAATimeout(t *testing.T) {
	va, _ := setup(nil, 0, "", nil, caaMockDNS{})

	params := &caaParams{
		accountURIID:     12345,
		validationMethod: core.ChallengeTypeHTTP01,
	}

	err := va.checkCAA(ctx, identifier.DNSIdentifier("caa-timeout.com"), params)
	test.AssertErrorIs(t, err, berrors.DNS)
	test.AssertContains(t, err.Error(), "error")
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

	va, _ := setup(nil, 0, "", nil, caaMockDNS{})
	va.accountURIPrefixes = []string{"https://letsencrypt.org/acct/reg/"}

	for _, caaTest := range testCases {
		mockLog := va.log.(*blog.Mock)
		defer mockLog.Clear()
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
	va, _ := setup(nil, 0, "", nil, caaMockDNS{})

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
			defer mockLog.Clear()

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
	va, _ := setup(nil, 0, "", nil, caaMockDNS{})

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
	va, _ := setup(nil, 0, "", nil, caaMockDNS{})

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

var errCAABrokenDNSClient = errors.New("dnsClient is broken")

// caaBrokenDNS implements the `dns.DNSClient` interface, but always returns
// errors.
type caaBrokenDNS struct{}

func (b caaBrokenDNS) LookupTXT(_ context.Context, hostname string) ([]string, bdns.ResolverAddrs, error) {
	return nil, bdns.ResolverAddrs{"caaBrokenDNS"}, errCAABrokenDNSClient
}

func (b caaBrokenDNS) LookupHost(_ context.Context, hostname string) ([]net.IP, bdns.ResolverAddrs, error) {
	return nil, bdns.ResolverAddrs{"caaBrokenDNS"}, errCAABrokenDNSClient
}

func (b caaBrokenDNS) LookupCAA(_ context.Context, domain string) ([]*dns.CAA, string, bdns.ResolverAddrs, error) {
	return nil, "", bdns.ResolverAddrs{"caaBrokenDNS"}, errCAABrokenDNSClient
}

func TestDisabledMultiCAARechecking(t *testing.T) {
	brokenRVA := setupRemote(nil, "broken", caaBrokenDNS{})
	remoteVAs := []RemoteVA{{brokenRVA, "broken"}}
	va, _ := setup(nil, 0, "local", remoteVAs, nil)

	features.Set(features.Config{
		EnforceMultiCAA:     false,
		MultiCAAFullResults: false,
	})
	defer features.Reset()

	isValidRes, err := va.IsCAAValid(context.TODO(), &vapb.IsCAAValidRequest{
		Domain:           "present.com",
		ValidationMethod: string(core.ChallengeTypeDNS01),
		AccountURIID:     1,
	})
	test.AssertNotError(t, err, "Error during IsCAAValid")
	// The primary VA can successfully recheck the CAA record and is allowed to
	// issue for this domain. If `EnforceMultiCAA`` was enabled, the configured
	// remote VA with broken dns.Client would fail the check and return a
	// Problem, but that code path could never trigger.
	test.AssertBoxedNil(t, isValidRes.Problem, "IsCAAValid returned a problem, but should not have")
}

// caaHijackedDNS implements the `dns.DNSClient` interface with a set of useful
// test answers for CAA queries. It returns alternate CAA records than what
// caaMockDNS returns simulating either a BGP hijack or DNS records that have
// changed while queries were inflight.
type caaHijackedDNS struct{}

func (h caaHijackedDNS) LookupTXT(_ context.Context, hostname string) ([]string, bdns.ResolverAddrs, error) {
	return nil, bdns.ResolverAddrs{"caaHijackedDNS"}, nil
}

func (h caaHijackedDNS) LookupHost(_ context.Context, hostname string) ([]net.IP, bdns.ResolverAddrs, error) {
	ip := net.ParseIP("127.0.0.1")
	return []net.IP{ip}, bdns.ResolverAddrs{"caaHijackedDNS"}, nil
}
func (h caaHijackedDNS) LookupCAA(_ context.Context, domain string) ([]*dns.CAA, string, bdns.ResolverAddrs, error) {
	// These records are altered from their caaMockDNS counterparts. Use this to
	// tickle remoteValidationFailures.
	var results []*dns.CAA
	var record dns.CAA
	switch strings.TrimRight(domain, ".") {
	case "present.com", "present.servfail.com":
		record.Tag = "issue"
		record.Value = "other-ca.com"
		results = append(results, &record)
	case "present-dns-only.com":
		return results, "", bdns.ResolverAddrs{"caaHijackedDNS"}, fmt.Errorf("SERVFAIL")
	case "satisfiable-wildcard.com":
		record.Tag = "issuewild"
		record.Value = ";"
		results = append(results, &record)
		secondRecord := record
		secondRecord.Tag = "issue"
		secondRecord.Value = ";"
		results = append(results, &secondRecord)
	}
	var response string
	if len(results) > 0 {
		response = "foo"
	}
	return results, response, bdns.ResolverAddrs{"caaHijackedDNS"}, nil
}

func TestMultiCAARechecking(t *testing.T) {
	// The remote differential log order is non-deterministic, so let's use
	// the same UA for all applicable RVAs.
	const (
		localUA    = "local"
		remoteUA   = "remote"
		brokenUA   = "broken"
		hijackedUA = "hijacked"
	)
	remoteVA := setupRemote(nil, remoteUA, nil)
	brokenVA := setupRemote(nil, brokenUA, caaBrokenDNS{})
	// Returns incorrect results
	hijackedVA := setupRemote(nil, hijackedUA, caaHijackedDNS{})

	testCases := []struct {
		name                     string
		maxLookupFailures        int
		domains                  string
		remoteVAs                []RemoteVA
		expectedProbSubstring    string
		expectedProbType         probs.ProblemType
		expectedDiffLogSubstring string
		localDNSClient           bdns.Client
	}{
		{
			name:           "all VAs functional, no CAA records",
			domains:        "present-dns-only.com",
			localDNSClient: caaMockDNS{},
			remoteVAs: []RemoteVA{
				{remoteVA, remoteUA},
				{remoteVA, remoteUA},
				{remoteVA, remoteUA},
			},
		},
		{
			name:                  "broken localVA, RVAs functional, no CAA records",
			domains:               "present-dns-only.com",
			localDNSClient:        caaBrokenDNS{},
			expectedProbSubstring: "While processing CAA for present-dns-only.com: dnsClient is broken",
			expectedProbType:      probs.DNSProblem,
			remoteVAs: []RemoteVA{
				{remoteVA, remoteUA},
				{remoteVA, remoteUA},
				{remoteVA, remoteUA},
			},
		},
		{
			name:                     "functional localVA, 1 broken RVA, no CAA records",
			domains:                  "present-dns-only.com",
			expectedProbSubstring:    "During secondary CAA checking: While processing CAA",
			expectedProbType:         probs.DNSProblem,
			expectedDiffLogSubstring: `RemoteSuccesses":2,"RemoteFailures":[{"VAHostname":"broken","Problem":{"type":"dns","detail":"While processing CAA for`,
			localDNSClient:           caaMockDNS{},
			remoteVAs: []RemoteVA{
				{brokenVA, brokenUA},
				{remoteVA, remoteUA},
				{remoteVA, remoteUA},
			},
		},
		{
			name:                     "functional localVA, all broken RVAs, no CAA records",
			domains:                  "present-dns-only.com",
			expectedProbSubstring:    "During secondary CAA checking: While processing CAA",
			expectedProbType:         probs.DNSProblem,
			expectedDiffLogSubstring: `RemoteSuccesses":0,"RemoteFailures":[{"VAHostname":"broken","Problem":{"type":"dns","detail":"While processing CAA for`,
			localDNSClient:           caaMockDNS{},
			remoteVAs: []RemoteVA{
				{brokenVA, brokenUA},
				{brokenVA, brokenUA},
				{brokenVA, brokenUA},
			},
		},
		{
			name:           "all VAs functional, CAA issue type present",
			domains:        "present.com",
			localDNSClient: caaMockDNS{},
			remoteVAs: []RemoteVA{
				{remoteVA, remoteUA},
				{remoteVA, remoteUA},
				{remoteVA, remoteUA},
			},
		},
		{
			name:                     "functional localVA, 1 broken RVA, CAA issue type present",
			domains:                  "present.com",
			expectedProbSubstring:    "During secondary CAA checking: While processing CAA",
			expectedProbType:         probs.DNSProblem,
			expectedDiffLogSubstring: `RemoteSuccesses":2,"RemoteFailures":[{"VAHostname":"broken","Problem":{"type":"dns","detail":"While processing CAA for`,
			localDNSClient:           caaMockDNS{},
			remoteVAs: []RemoteVA{
				{brokenVA, brokenUA},
				{remoteVA, remoteUA},
				{remoteVA, remoteUA},
			},
		},
		{
			name:                     "functional localVA, all broken RVAs, CAA issue type present",
			domains:                  "present.com",
			expectedProbSubstring:    "During secondary CAA checking: While processing CAA",
			expectedProbType:         probs.DNSProblem,
			expectedDiffLogSubstring: `RemoteSuccesses":0,"RemoteFailures":[{"VAHostname":"broken","Problem":{"type":"dns","detail":"While processing CAA for`,
			localDNSClient:           caaMockDNS{},
			remoteVAs: []RemoteVA{
				{brokenVA, brokenUA},
				{brokenVA, brokenUA},
				{brokenVA, brokenUA},
			},
		},
		{
			// The localVA kicks off the background goroutines before doing its
			// own check. But if its own check fails, it doesn't wait for their
			// results.
			name:                  "all VAs functional, CAA issue type forbids issuance",
			domains:               "unsatisfiable.com",
			expectedProbSubstring: "CAA record for unsatisfiable.com prevents issuance",
			expectedProbType:      probs.CAAProblem,
			localDNSClient:        caaMockDNS{},
			remoteVAs: []RemoteVA{
				{remoteVA, remoteUA},
				{remoteVA, remoteUA},
				{remoteVA, remoteUA},
			},
		},
		{
			name:                     "1 hijacked RVA, CAA issue type present",
			domains:                  "present.com",
			expectedProbSubstring:    "CAA record for present.com prevents issuance",
			expectedProbType:         probs.CAAProblem,
			expectedDiffLogSubstring: `RemoteSuccesses":2,"RemoteFailures":[{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for`,
			localDNSClient:           caaMockDNS{},
			remoteVAs: []RemoteVA{
				{hijackedVA, hijackedUA},
				{remoteVA, remoteUA},
				{remoteVA, remoteUA},
			},
		},
		{
			name:                     "2 hijacked RVAs, CAA issue type present",
			domains:                  "present.com",
			expectedProbSubstring:    "During secondary CAA checking: While processing CAA",
			expectedProbType:         probs.CAAProblem,
			expectedDiffLogSubstring: `RemoteSuccesses":1,"RemoteFailures":[{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for`,
			localDNSClient:           caaMockDNS{},
			remoteVAs: []RemoteVA{
				{hijackedVA, hijackedUA},
				{hijackedVA, hijackedUA},
				{remoteVA, remoteUA},
			},
		},
		{
			name:                     "3 hijacked RVAs, CAA issue type present",
			domains:                  "present.com",
			expectedProbSubstring:    "During secondary CAA checking: While processing CAA",
			expectedProbType:         probs.CAAProblem,
			expectedDiffLogSubstring: `RemoteSuccesses":0,"RemoteFailures":[{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for`,
			localDNSClient:           caaMockDNS{},
			remoteVAs: []RemoteVA{
				{hijackedVA, hijackedUA},
				{hijackedVA, hijackedUA},
				{hijackedVA, hijackedUA},
			},
		},
		{
			name:                     "1 hijacked RVA, CAA issuewild type present",
			domains:                  "satisfiable-wildcard.com",
			expectedProbSubstring:    "During secondary CAA checking: While processing CAA",
			expectedProbType:         probs.CAAProblem,
			expectedDiffLogSubstring: `RemoteSuccesses":2,"RemoteFailures":[{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for`,
			localDNSClient:           caaMockDNS{},
			remoteVAs: []RemoteVA{
				{hijackedVA, hijackedUA},
				{remoteVA, remoteUA},
				{remoteVA, remoteUA},
			},
		},
		{
			name:                     "2 hijacked RVAs, CAA issuewild type present",
			domains:                  "satisfiable-wildcard.com",
			expectedProbSubstring:    "During secondary CAA checking: While processing CAA",
			expectedProbType:         probs.CAAProblem,
			expectedDiffLogSubstring: `RemoteSuccesses":1,"RemoteFailures":[{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for`,
			localDNSClient:           caaMockDNS{},
			remoteVAs: []RemoteVA{
				{hijackedVA, hijackedUA},
				{hijackedVA, hijackedUA},
				{remoteVA, remoteUA},
			},
		},
		{
			name:                     "3 hijacked RVAs, CAA issuewild type present",
			domains:                  "satisfiable-wildcard.com",
			expectedProbSubstring:    "During secondary CAA checking: While processing CAA",
			expectedProbType:         probs.CAAProblem,
			expectedDiffLogSubstring: `RemoteSuccesses":0,"RemoteFailures":[{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for`,
			localDNSClient:           caaMockDNS{},
			remoteVAs: []RemoteVA{
				{hijackedVA, hijackedUA},
				{hijackedVA, hijackedUA},
				{hijackedVA, hijackedUA},
			},
		},
		{
			name:                     "1 hijacked RVA, CAA issuewild type present, 1 failure allowed",
			domains:                  "satisfiable-wildcard.com",
			maxLookupFailures:        1,
			expectedDiffLogSubstring: `RemoteSuccesses":2,"RemoteFailures":[{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for`,
			localDNSClient:           caaMockDNS{},
			remoteVAs: []RemoteVA{
				{hijackedVA, hijackedUA},
				{remoteVA, remoteUA},
				{remoteVA, remoteUA},
			},
		},
		{
			name:                     "2 hijacked RVAs, CAA issuewild type present, 1 failure allowed",
			domains:                  "satisfiable-wildcard.com",
			maxLookupFailures:        1,
			expectedProbSubstring:    "During secondary CAA checking: While processing CAA",
			expectedProbType:         probs.CAAProblem,
			expectedDiffLogSubstring: `RemoteSuccesses":1,"RemoteFailures":[{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for`,
			localDNSClient:           caaMockDNS{},
			remoteVAs: []RemoteVA{
				{hijackedVA, hijackedUA},
				{hijackedVA, hijackedUA},
				{remoteVA, remoteUA},
			},
		},
		{
			name:                     "3 hijacked RVAs, CAA issuewild type present, 1 failure allowed",
			domains:                  "satisfiable-wildcard.com",
			maxLookupFailures:        1,
			expectedProbSubstring:    "During secondary CAA checking: While processing CAA",
			expectedProbType:         probs.CAAProblem,
			expectedDiffLogSubstring: `RemoteSuccesses":0,"RemoteFailures":[{"VAHostname":"hijacked","Problem":{"type":"caa","detail":"While processing CAA for`,
			localDNSClient:           caaMockDNS{},
			remoteVAs: []RemoteVA{
				{hijackedVA, hijackedUA},
				{hijackedVA, hijackedUA},
				{hijackedVA, hijackedUA},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			va, mockLog := setup(nil, tc.maxLookupFailures, localUA, tc.remoteVAs, tc.localDNSClient)
			defer mockLog.Clear()

			// MultiCAAFullResults: false is inherently flaky because of the
			// non-deterministic nature of concurrent goroutine returns. We,
			// boulder dev, made a decision to skip testing that path and
			// eventually make MultiCAAFullResults: true the default.
			features.Set(features.Config{
				EnforceMultiCAA:     true,
				MultiCAAFullResults: true,
			})
			defer features.Reset()

			isValidRes, err := va.IsCAAValid(context.TODO(), &vapb.IsCAAValidRequest{
				Domain:           tc.domains,
				ValidationMethod: string(core.ChallengeTypeDNS01),
				AccountURIID:     1,
			})
			test.AssertNotError(t, err, "Should not have errored, but did")

			if tc.expectedProbSubstring != "" {
				test.AssertContains(t, isValidRes.Problem.Detail, tc.expectedProbSubstring)
			} else if isValidRes.Problem != nil {
				test.AssertBoxedNil(t, isValidRes.Problem, "IsCAAValidRequest returned a problem, but should not have")
			}

			if tc.expectedProbType != "" {
				test.AssertEquals(t, string(tc.expectedProbType), isValidRes.Problem.ProblemType)
			}

			var invalidRVACount int
			for _, x := range va.remoteVAs {
				if x.Address == "broken" || x.Address == "hijacked" {
					invalidRVACount++
				}
			}

			gotRequestProbs := mockLog.GetAllMatching(".IsCAAValid returned problem: ")
			test.AssertEquals(t, len(gotRequestProbs), invalidRVACount)

			gotDifferential := mockLog.GetAllMatching("remoteVADifferentials JSON=.*")
			if features.Get().MultiCAAFullResults && tc.expectedDiffLogSubstring != "" {
				test.AssertEquals(t, len(gotDifferential), 1)
				test.AssertContains(t, gotDifferential[0], tc.expectedDiffLogSubstring)
			} else {
				test.AssertEquals(t, len(gotDifferential), 0)
			}

			gotAnyRemoteFailures := mockLog.GetAllMatching("CAA check failed due to remote failures:")
			if len(gotAnyRemoteFailures) >= 1 {
				// The primary VA only emits this line once.
				test.AssertEquals(t, len(gotAnyRemoteFailures), 1)
			} else {
				test.AssertEquals(t, len(gotAnyRemoteFailures), 0)
			}
		})
	}
}

func TestCAAFailure(t *testing.T) {
	hs := httpSrv(t, expectedToken)
	defer hs.Close()

	va, _ := setup(hs, 0, "", nil, caaMockDNS{})

	err := va.checkCAA(ctx, dnsi("reserved.com"), &caaParams{1, core.ChallengeTypeHTTP01})
	if err == nil {
		t.Fatalf("Expected CAA rejection for reserved.com, got success")
	}
	test.AssertErrorIs(t, err, berrors.CAA)

	err = va.checkCAA(ctx, dnsi("example.gonetld"), &caaParams{1, core.ChallengeTypeHTTP01})
	if err == nil {
		t.Fatalf("Expected CAA rejection for gonetld, got success")
	}
	prob := detailedError(err)
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
				{Tag: "issuemail", Value: "c"},
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
				{Tag: "issuemail", Value: "c", Flag: 128},
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
		{"", false, nil, nil, false, "", nil, nil},
		{"", false, nil, nil, false, "", nil, nil},
		{"", false, nil, nil, false, "", nil, nil},
	}
	s, err = selectCAA(r)
	test.Assert(t, s == nil, "set is not nil")
	test.AssertNotError(t, err, "error is not nil")

	// A slice of caaResults containing an error followed by a CAA
	// record should return the error
	r = []caaResult{
		{"foo.com", false, nil, nil, false, "", nil, errors.New("oops")},
		{"com", true, []*dns.CAA{&expected}, nil, false, "foo", nil, nil},
	}
	s, err = selectCAA(r)
	test.Assert(t, s == nil, "set is not nil")
	test.AssertError(t, err, "error is nil")
	test.AssertEquals(t, err.Error(), "oops")

	//  A slice of caaResults containing a good record that precedes an
	//  error, should return that good record, not the error
	r = []caaResult{
		{"foo.com", true, []*dns.CAA{&expected}, nil, false, "foo", nil, nil},
		{"com", false, nil, nil, false, "", nil, errors.New("")},
	}
	s, err = selectCAA(r)
	test.AssertEquals(t, len(s.issue), 1)
	test.Assert(t, s.issue[0] == &expected, "Incorrect record returned")
	test.AssertEquals(t, s.dig, "foo")
	test.Assert(t, err == nil, "error is not nil")

	// A slice of caaResults containing multiple CAA records should
	// return the first non-empty CAA record
	r = []caaResult{
		{"bar.foo.com", false, []*dns.CAA{}, []*dns.CAA{}, false, "", nil, nil},
		{"foo.com", true, []*dns.CAA{&expected}, nil, false, "foo", nil, nil},
		{"com", true, []*dns.CAA{&expected}, nil, false, "bar", nil, nil},
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
