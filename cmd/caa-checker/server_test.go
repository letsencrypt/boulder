package main

import (
	"testing"

	"github.com/cactus/go-statsd-client/statsd"
	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/bdns"
	pb "github.com/letsencrypt/boulder/cmd/caa-checker/proto"
	"github.com/letsencrypt/boulder/test"
)

func TestChecking(t *testing.T) {
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

	stats, _ := statsd.NewNoopClient()
	ccs := &caaCheckerServer{&bdns.MockDNSResolver{}, stats}
	issuerDomain := "letsencrypt.org"

	ctx := context.Background()

	for _, caaTest := range tests {
		result, err := ccs.ValidForIssuance(ctx, &pb.Check{Name: &caaTest.Domain, IssuerDomain: &issuerDomain})
		if err != nil {
			t.Errorf("CheckCAARecords error for %s: %s", caaTest.Domain, err)
		}
		if *result.Present != caaTest.Present {
			t.Errorf("CheckCAARecords presence mismatch for %s: got %t expected %t", caaTest.Domain, *result.Present, caaTest.Present)
		}
		if *result.Valid != caaTest.Valid {
			t.Errorf("CheckCAARecords presence mismatch for %s: got %t expected %t", caaTest.Domain, *result.Valid, caaTest.Valid)
		}
	}

	servfail := "servfail.com"
	servfailPresent := "servfail.present.com"
	result, err := ccs.ValidForIssuance(ctx, &pb.Check{Name: &servfail, IssuerDomain: &issuerDomain})
	test.AssertError(t, err, "servfail.com")
	test.Assert(t, result == nil, "result should be nil")

	result, err = ccs.ValidForIssuance(ctx, &pb.Check{Name: &servfailPresent, IssuerDomain: &issuerDomain})
	test.AssertError(t, err, "servfail.present.com")
	test.Assert(t, result == nil, "result should be nil")
}
