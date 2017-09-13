package va

import (
	"errors"
	"testing"

	"github.com/miekg/dns"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"
)

func TestTreeClimbNotPresent(t *testing.T) {
	target := "deep-cname.not-present.com"
	_ = features.Set(map[string]bool{"LegacyCAA": true})
	va, _ := setup(nil, 0)
	prob := va.checkCAA(ctx, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: target})
	if prob != nil {
		t.Fatalf("Expected success for %q, got %s", target, prob)
	}
}

func TestDeepTreeClimb(t *testing.T) {
	// The ultimate target of the CNAME has a CAA record preventing issuance, but
	// the parent of the FQDN has a CAA record permitting. The target of the CNAME
	// takes precedence.
	target := "deep-cname.present-with-parameter.com"
	_ = features.Set(map[string]bool{"LegacyCAA": true})
	va, _ := setup(nil, 0)
	prob := va.checkCAA(ctx, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: target})
	if prob == nil {
		t.Fatalf("Expected error for %q, got none", target)
	}
}

func TestTreeClimbingLookupCAASimpleSuccess(t *testing.T) {
	target := "www.present-with-parameter.com"
	_ = features.Set(map[string]bool{"LegacyCAA": true})
	va, _ := setup(nil, 0)
	prob := va.checkCAA(ctx, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: target})
	if prob != nil {
		t.Fatalf("Expected success for %q, got %s", target, prob)
	}
}

func TestTreeClimbingLookupCAALimitHit(t *testing.T) {
	target := "blog.cname-to-subdomain.com"
	_ = features.Set(map[string]bool{"LegacyCAA": true})
	va, _ := setup(nil, 0)
	prob := va.checkCAA(ctx, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: target})
	if prob == nil {
		t.Fatalf("Expected failure for %q, got success", target)
	}
}

func TestCNAMEToReserved(t *testing.T) {
	target := "cname-to-reserved.com"
	_ = features.Set(map[string]bool{"LegacyCAA": true})
	va, _ := setup(nil, 0)
	prob := va.checkCAA(ctx, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: target})
	if prob == nil {
		t.Fatalf("Expected error for cname-to-reserved.com, got success")
	}
	if prob.Type != probs.ConnectionProblem {
		t.Errorf("Expected timeout error type %s, got %s", probs.ConnectionProblem, prob.Type)
	}
	expected := "CAA record for cname-to-reserved.com prevents issuance"
	if prob.Detail != expected {
		t.Errorf("checkCAA: got %#v, expected %#v", prob.Detail, expected)
	}
}

func TestCAATimeout(t *testing.T) {
	va, _ := setup(nil, 0)
	err := va.checkCAA(ctx, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "caa-timeout.com"})
	if err.Type != probs.ConnectionProblem {
		t.Errorf("Expected timeout error type %s, got %s", probs.ConnectionProblem, err.Type)
	}
	expected := "DNS problem: query timed out looking up CAA for always.timeout"
	if err.Detail != expected {
		t.Errorf("checkCAA: got %#v, expected %#v", err.Detail, expected)
	}
}

func TestCAAChecking(t *testing.T) {
	type CAATest struct {
		Domain  string
		Present bool
		Valid   bool
	}
	tests := []CAATest{
		// Reserved
		{"reserved.com", true, false},
		// Critical
		{"critical.com", true, false},
		{"nx.critical.com", true, false},
		// Good (absent)
		{"absent.com", false, true},
		{"example.co.uk", false, true},
		// Good (present)
		{"present.com", true, true},
		{"present.servfail.com", true, true},
		// Good (multiple critical, one matching)
		{"multi-crit-present.com", true, true},
		// Bad (unknown critical)
		{"unknown-critical.com", true, false},
		{"unknown-critical2.com", true, false},
		// Good (unknown noncritical, no issue/issuewild records)
		{"unknown-noncritical.com", true, true},
		// Good (issue record with unknown parameters)
		{"present-with-parameter.com", true, true},
		// Bad (unsatisfiable issue record)
		{"unsatisfiable.com", true, false},
	}

	va, _ := setup(nil, 0)
	for _, caaTest := range tests {
		present, valid, err := va.checkCAARecords(ctx, core.AcmeIdentifier{Type: "dns", Value: caaTest.Domain})
		if err != nil {
			t.Errorf("checkCAARecords error for %s: %s", caaTest.Domain, err)
		}
		if present != caaTest.Present {
			t.Errorf("checkCAARecords presence mismatch for %s: got %t expected %t", caaTest.Domain, present, caaTest.Present)
		}
		if valid != caaTest.Valid {
			t.Errorf("checkCAARecords validity mismatch for %s: got %t expected %t", caaTest.Domain, valid, caaTest.Valid)
		}
	}

	present, valid, err := va.checkCAARecords(ctx, core.AcmeIdentifier{Type: "dns", Value: "servfail.com"})
	test.AssertError(t, err, "servfail.com")
	test.Assert(t, !present, "Present should be false")
	test.Assert(t, !valid, "Valid should be false")

	_, _, err = va.checkCAARecords(ctx, core.AcmeIdentifier{Type: "dns", Value: "servfail.com"})
	if err == nil {
		t.Errorf("Should have returned error on CAA lookup, but did not: %s", "servfail.com")
	}

	present, valid, err = va.checkCAARecords(ctx, core.AcmeIdentifier{Type: "dns", Value: "servfail.present.com"})
	test.AssertError(t, err, "servfail.present.com")
	test.Assert(t, !present, "Present should be false")
	test.Assert(t, !valid, "Valid should be false")

	_, _, err = va.checkCAARecords(ctx, core.AcmeIdentifier{Type: "dns", Value: "servfail.present.com"})
	if err == nil {
		t.Errorf("Should have returned error on CAA lookup, but did not: %s", "servfail.present.com")
	}
}

func TestCAAFailure(t *testing.T) {
	chall := createChallenge(core.ChallengeTypeTLSSNI01)
	hs := tlssni01Srv(t, chall)
	defer hs.Close()

	va, _ := setup(hs, 0)

	_, prob := va.validateChallengeAndCAA(ctx, dnsi("reserved.com"), chall)
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)
}

func TestParseResults(t *testing.T) {
	r := []caaResult{}
	s, err := parseResults(r)
	test.Assert(t, s == nil, "set is not nil")
	test.Assert(t, err == nil, "error is not nil")
	test.AssertNotError(t, err, "no error should be returned")
	r = []caaResult{{nil, errors.New("")}, {[]*dns.CAA{{Value: "test"}}, nil}}
	s, err = parseResults(r)
	test.Assert(t, s == nil, "set is not nil")
	test.AssertEquals(t, err.Error(), "")
	expected := dns.CAA{Value: "other-test"}
	r = []caaResult{{[]*dns.CAA{&expected}, nil}, {[]*dns.CAA{{Value: "test"}}, nil}}
	s, err = parseResults(r)
	test.AssertEquals(t, len(s.Unknown), 1)
	test.Assert(t, s.Unknown[0] == &expected, "Incorrect record returned")
	test.AssertNotError(t, err, "no error should be returned")
}
