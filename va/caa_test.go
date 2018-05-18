package va

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"

	blog "github.com/letsencrypt/boulder/log"
	vapb "github.com/letsencrypt/boulder/va/proto"
)

// caaMockDNS implements the `dns.DNSClient` interface with a set of useful test
// answers for CAA queries.
type caaMockDNS struct{}

func (mock caaMockDNS) LookupTXT(_ context.Context, hostname string) ([]string, []string, error) {
	return nil, nil, nil
}

func (mock caaMockDNS) LookupHost(_ context.Context, hostname string) ([]net.IP, error) {
	ip := net.ParseIP("127.0.0.1")
	return []net.IP{ip}, nil
}

func (mock caaMockDNS) LookupMX(_ context.Context, domain string) ([]string, error) {
	return nil, nil
}

func (mock caaMockDNS) LookupCAA(_ context.Context, domain string) ([]*dns.CAA, error) {
	var results []*dns.CAA
	var record dns.CAA
	switch strings.TrimRight(domain, ".") {
	case "caa-timeout.com":
		return nil, fmt.Errorf("error")
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
		return nil, nil
	case "servfail.com", "servfail.present.com":
		return results, fmt.Errorf("SERVFAIL")
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
	return results, nil
}

func TestCAATimeout(t *testing.T) {
	va, _ := setup(nil, 0)
	va.dnsClient = caaMockDNS{}
	err := va.checkCAA(ctx, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "caa-timeout.com"})
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
		Present bool
		Valid   bool
	}{
		{
			Name:    "Bad (Reserved)",
			Domain:  "reserved.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Bad (Reserved, Mixed case Issue)",
			Domain:  "mixedcase.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Bad (Critical)",
			Domain:  "critical.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Bad (NX Critical)",
			Domain:  "nx.critical.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Good (absent)",
			Domain:  "absent.com",
			Present: false,
			Valid:   true,
		},
		{
			Name:    "Good (Example.co.uk, absent)",
			Domain:  "example.co.uk",
			Present: false,
			Valid:   true,
		},
		{
			Name:    "Good (present and valid)",
			Domain:  "present.com",
			Present: true,
			Valid:   true,
		},
		{
			Name:    "Good (Present w/ servfail exception?)",
			Domain:  "present.servfail.com",
			Present: true,
			Valid:   true,
		},
		{
			Name:    "Good (multiple critical, one matching)",
			Domain:  "multi-crit-present.com",
			Present: true,
			Valid:   true,
		},
		{
			Name:    "Bad (unknown critical)",
			Domain:  "unknown-critical.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Bad (unknown critical 2)",
			Domain:  "unknown-critical2.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Good (unknown non-critical, no issue/issuewild)",
			Domain:  "unknown-noncritical.com",
			Present: true,
			Valid:   true,
		},
		{
			Name:    "Good (issue rec with unknown params)",
			Domain:  "present-with-parameter.com",
			Present: true,
			Valid:   true,
		},
		{
			Name:    "Bad (unsatisfiable issue record)",
			Domain:  "unsatisfiable.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Bad (unsatisfiable issue, wildcard)",
			Domain:  "*.unsatisfiable.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Bad (unsatisfiable wildcard)",
			Domain:  "*.unsatisfiable-wildcard.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Bad (unsatisfiable wildcard override)",
			Domain:  "*.unsatisfiable-wildcard-override.com",
			Present: true,
			Valid:   false,
		},
		{
			Name:    "Good (satisfiable wildcard)",
			Domain:  "*.satisfiable-wildcard.com",
			Present: true,
			Valid:   true,
		},
		{
			Name:    "Good (multiple issuewild, one satisfiable)",
			Domain:  "*.satisfiable-multi-wildcard.com",
			Present: true,
			Valid:   true,
		},
		{
			Name:    "Good (satisfiable wildcard override)",
			Domain:  "*.satisfiable-wildcard-override.com",
			Present: true,
			Valid:   true,
		},
	}

	va, _ := setup(nil, 0)
	va.dnsClient = caaMockDNS{}
	for _, caaTest := range testCases {
		mockLog := va.log.(*blog.Mock)
		mockLog.Clear()
		t.Run(caaTest.Name, func(t *testing.T) {
			present, valid, _, err := va.checkCAARecords(ctx, core.AcmeIdentifier{Type: "dns", Value: caaTest.Domain})
			if err != nil {
				t.Errorf("checkCAARecords error for %s: %s", caaTest.Domain, err)
			}
			if present != caaTest.Present {
				t.Errorf("checkCAARecords presence mismatch for %s: got %t expected %t", caaTest.Domain, present, caaTest.Present)
			}
			if valid != caaTest.Valid {
				t.Errorf("checkCAARecords validity mismatch for %s: got %t expected %t", caaTest.Domain, valid, caaTest.Valid)
			}
		})
	}

	present, valid, _, err := va.checkCAARecords(ctx, core.AcmeIdentifier{Type: "dns", Value: "servfail.com"})
	test.AssertError(t, err, "servfail.com")
	test.Assert(t, !present, "Present should be false")
	test.Assert(t, !valid, "Valid should be false")

	_, _, _, err = va.checkCAARecords(ctx, core.AcmeIdentifier{Type: "dns", Value: "servfail.com"})
	if err == nil {
		t.Errorf("Should have returned error on CAA lookup, but did not: %s", "servfail.com")
	}

	present, valid, _, err = va.checkCAARecords(ctx, core.AcmeIdentifier{Type: "dns", Value: "servfail.present.com"})
	test.AssertError(t, err, "servfail.present.com")
	test.Assert(t, !present, "Present should be false")
	test.Assert(t, !valid, "Valid should be false")

	_, _, _, err = va.checkCAARecords(ctx, core.AcmeIdentifier{Type: "dns", Value: "servfail.present.com"})
	if err == nil {
		t.Errorf("Should have returned error on CAA lookup, but did not: %s", "servfail.present.com")
	}
}

func TestCAALogging(t *testing.T) {
	va, _ := setup(nil, 0)
	va.dnsClient = caaMockDNS{}

	testCases := []struct {
		Name            string
		Domain          string
		ExpectedLogline string
	}{
		{
			Domain:          "reserved.com",
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for reserved.com, [Present: true, Valid for issuance: false] Records=[\"\\t0\\tCLASS0\\tNone\\t0 issue \\\"ca.com\\\"\"]",
		},
		{
			Domain:          "mixedcase.com",
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for mixedcase.com, [Present: true, Valid for issuance: false] Records=[\"\\t0\\tCLASS0\\tNone\\t0 iSsUe \\\"ca.com\\\"\"]",
		},
		{
			Domain:          "critical.com",
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for critical.com, [Present: true, Valid for issuance: false] Records=[\"\\t0\\tCLASS0\\tNone\\t1 issue \\\"ca.com\\\"\"]",
		},
		{
			Domain:          "present.com",
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for present.com, [Present: true, Valid for issuance: true] Records=[\"\\t0\\tCLASS0\\tNone\\t0 issue \\\"letsencrypt.org\\\"\"]",
		},
		{
			Domain:          "multi-crit-present.com",
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for multi-crit-present.com, [Present: true, Valid for issuance: true] Records=[\"\\t0\\tCLASS0\\tNone\\t1 issue \\\"ca.com\\\"\",\"\\t0\\tCLASS0\\tNone\\t1 issue \\\"letsencrypt.org\\\"\"]",
		},
		{
			Domain:          "present-with-parameter.com",
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for present-with-parameter.com, [Present: true, Valid for issuance: true] Records=[\"\\t0\\tCLASS0\\tNone\\t0 issue \\\"  letsencrypt.org  ;foo=bar;baz=bar\\\"\"]",
		},
		{
			Domain:          "satisfiable-wildcard-override.com",
			ExpectedLogline: "INFO: [AUDIT] Checked CAA records for satisfiable-wildcard-override.com, [Present: true, Valid for issuance: false] Records=[\"\\t0\\tCLASS0\\tNone\\t0 issue \\\"ca.com\\\"\",\"\\t0\\tCLASS0\\tNone\\t0 issuewild \\\"letsencrypt.org\\\"\"]",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Domain, func(t *testing.T) {
			mockLog := va.log.(*blog.Mock)
			mockLog.Clear()

			_ = va.checkCAA(ctx, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: tc.Domain})

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
	va, _ := setup(nil, 0)
	va.dnsClient = caaMockDNS{}

	// Call IsCAAValid with a domain we know fails with a generic error from the
	// caaMockDNS.
	domain := "caa-timeout.com"
	resp, err := va.IsCAAValid(ctx, &vapb.IsCAAValidRequest{
		Domain: &domain,
	})

	// The lookup itself should not return an error
	test.AssertNotError(t, err, "Unexpected error calling IsCAAValidRequest")
	// The result should not be nil
	test.AssertNotNil(t, resp, "Response to IsCAAValidRequest was nil")
	// The result's Problem should not be nil
	test.AssertNotNil(t, resp.Problem, "Response Problem was nil")
	// The result's Problem should be an error message that includes the domain.
	test.AssertEquals(t, *resp.Problem.Detail, fmt.Sprintf("While processing CAA for %s: error", domain))
}

func TestCAAFailure(t *testing.T) {
	chall := createChallenge(core.ChallengeTypeTLSSNI01)
	hs := tlssni01Srv(t, chall)
	defer hs.Close()

	va, _ := setup(hs, 0)
	va.dnsClient = caaMockDNS{}

	_, prob := va.validateChallengeAndIdentifier(ctx, dnsi("reserved.com"), chall)
	if prob == nil {
		t.Fatalf("Expected CAA rejection for reserved.com, got success")
	}
	test.AssertEquals(t, prob.Type, probs.CAAProblem)
}

func TestParseResults(t *testing.T) {
	r := []caaResult{}
	s, records, err := parseResults(r)
	test.Assert(t, s == nil, "set is not nil")
	test.Assert(t, err == nil, "error is not nil")
	test.Assert(t, records == nil, "records is not nil")
	test.AssertNotError(t, err, "no error should be returned")
	r = []caaResult{{nil, errors.New("")}, {[]*dns.CAA{{Value: "test"}}, nil}}
	s, records, err = parseResults(r)
	test.Assert(t, s == nil, "set is not nil")
	test.AssertEquals(t, err.Error(), "")
	expected := dns.CAA{Value: "other-test"}
	test.AssertEquals(t, len(records), 0)
	r = []caaResult{{[]*dns.CAA{&expected}, nil}, {[]*dns.CAA{{Value: "test"}}, nil}}
	s, records, err = parseResults(r)
	test.AssertEquals(t, len(s.Unknown), 1)
	test.Assert(t, s.Unknown[0] == &expected, "Incorrect record returned")
	test.AssertNotError(t, err, "no error should be returned")
	test.AssertEquals(t, len(records), len(r[0].records))
	for i, rec := range records {
		test.AssertEquals(t, rec.String(), r[0].records[i].String())
	}
}
