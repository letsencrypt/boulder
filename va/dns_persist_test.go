package va

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/letsencrypt/boulder/bdns"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"
)

type dnsPersistFakeDNS struct {
	bdns.Client
	records map[string][]string
	err     error
}

func (d *dnsPersistFakeDNS) LookupTXT(_ context.Context, hostname string) (*bdns.Result[*dns.TXT], string, error) {
	if d.err != nil {
		return nil, "dnsPersistFakeDNS", d.err
	}

	var rrs []*dns.TXT
	for _, txt := range d.records[hostname] {
		rrs = append(rrs, &dns.TXT{Txt: []string{txt}})
	}
	return &bdns.Result[*dns.TXT]{Final: rrs}, "dnsPersistFakeDNS", nil
}

func TestDNSPersist01Validation(t *testing.T) {
	t.Parallel()

	const (
		domain    = "example.com"
		challHost = "_validation-persist.example.com"
	)
	accountURI := accountURIPrefixes[0] + "1"

	testCases := []struct {
		name           string
		txtRecords     []string
		wildcard       bool
		dnsErr         error
		wantProbType   probs.ProblemType
		wantDetailLike string
	}{
		{
			name: "matching malformed and matching valid record succeeds",
			txtRecords: []string{
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/1;accounturi=http://letsencrypt.org:4000/acme/reg/2",
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/1",
			},
		},
		{
			name: "matching unauthorized and matching valid record succeeds",
			txtRecords: []string{
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/999",
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/1",
			},
		},
		{
			name: "unknown tags are ignored",
			txtRecords: []string{
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/1;bad tag=value;\nweird=\\x01337",
			},
		},
		{
			name: "issuer-domain-name is normalized before comparison (uppercase + trailing dot)",
			txtRecords: []string{
				"LETSENCRYPT.ORG.;accounturi=http://letsencrypt.org:4000/acme/reg/1",
			},
		},
		{
			name: "wildcard accepts case-insensitive policy value",
			txtRecords: []string{
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/1;policy=wIlDcArD",
			},
			wildcard: true,
		},
		{
			name:           "lookup failure returns DNS problem",
			dnsErr:         errors.New("SERVFAIL"),
			wantProbType:   probs.DNSProblem,
			wantDetailLike: "Retrieving TXT records for DNS-PERSIST-01 challenge",
		},
		{
			name:           "no txt records found returns unauthorized",
			wantProbType:   probs.UnauthorizedProblem,
			wantDetailLike: "No TXT record found for DNS-PERSIST-01 challenge",
		},
		{
			name: "only matching malformed record returns malformed",
			txtRecords: []string{
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/1;accounturi=http://letsencrypt.org:4000/acme/reg/2",
			},
			wantProbType:   probs.MalformedProblem,
			wantDetailLike: "duplicate parameter",
		},
		{
			name: "only matching unauthorized record returns unauthorized",
			txtRecords: []string{
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/999",
			},
			wantProbType:   probs.UnauthorizedProblem,
			wantDetailLike: "accounturi mismatch",
		},
		{
			name: "non-matching issuer-domain-name record is ignored",
			txtRecords: []string{
				"other.example;accounturi=http://letsencrypt.org:4000/acme/reg/1",
			},
			wantProbType:   probs.UnauthorizedProblem,
			wantDetailLike: "No valid TXT record found",
		},
		{
			name: "missing equals is malformed",
			txtRecords: []string{
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/1;invalidparam",
			},
			wantProbType:   probs.MalformedProblem,
			wantDetailLike: `malformed parameter "invalidparam" should be tag=value pair`,
		},
		{
			name: "empty tag is malformed",
			txtRecords: []string{
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/1;=abc",
			},
			wantProbType:   probs.MalformedProblem,
			wantDetailLike: `malformed parameter "=abc", empty tag`,
		},
		{
			name: "empty accounturi value is malformed",
			txtRecords: []string{
				"letsencrypt.org;accounturi=",
			},
			wantProbType:   probs.MalformedProblem,
			wantDetailLike: "empty value provided for mandatory accounturi",
		},
		{
			name: "invalid value character is malformed",
			txtRecords: []string{
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/1;policy=wild card",
			},
			wantProbType:   probs.MalformedProblem,
			wantDetailLike: `malformed value "wild card" for tag "policy"`,
		},
		{
			name: "persistUntil non unix timestamp is malformed",
			txtRecords: []string{
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/1;persistUntil=not-a-unix-timestamp",
			},
			wantProbType:   probs.MalformedProblem,
			wantDetailLike: `malformed persistUntil timestamp "not-a-unix-timestamp"`,
		},
		{
			name: "duplicate unknown parameter is ignored",
			txtRecords: []string{
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/1;foo=bar;foo=baz",
			},
		},
		{
			name: "matching record missing accounturi returns malformed",
			txtRecords: []string{
				"letsencrypt.org;policy=wildcard",
			},
			wantProbType:   probs.MalformedProblem,
			wantDetailLike: "missing mandatory accountURI parameter",
		},
		{
			name: "wildcard policy mismatch returns unauthorized",
			txtRecords: []string{
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/1;policy=notwildcard",
			},
			wildcard:       true,
			wantProbType:   probs.UnauthorizedProblem,
			wantDetailLike: `policy mismatch: expected "wildcard", got`,
		},
		{
			name: "trailing semicolon in matching record returns malformed",
			txtRecords: []string{
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/1;",
			},
			wantProbType:   probs.MalformedProblem,
			wantDetailLike: "empty parameter or trailing semicolon provided",
		},
		{
			name: "expired persistUntil returns unauthorized",
			txtRecords: []string{
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/1;persistUntil=-1",
			},
			wantProbType:   probs.UnauthorizedProblem,
			wantDetailLike: "validation time",
		},
		{
			name: "unknown tag with empty value is ignored",
			txtRecords: []string{
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/1;foo=",
			},
		},
		{
			name: "unknown tag with invalid-character value is ignored",
			txtRecords: []string{
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/1;futurefeature=value with spaces",
			},
		},
		{
			name: "all known fields with heavy whitespace",
			txtRecords: []string{
				"   letsencrypt.org   ;   accounturi   =   http://letsencrypt.org:4000/acme/reg/1   ;   policy   =   wildcard   ;   persistUntil   =   4102444800   ",
			},
			wildcard: true,
		},
		{
			name: "policy other than wildcard is treated as absent for non-wildcard request",
			txtRecords: []string{
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/1;policy=notwildcard",
			},
		},
		{
			name: "missing issuer-domain-name is ignored",
			txtRecords: []string{
				";accounturi=http://letsencrypt.org:4000/acme/reg/1",
			},
			wantProbType:   probs.UnauthorizedProblem,
			wantDetailLike: "No valid TXT record found",
		},
		{
			name: "duplicate parameter detection is case-insensitive",
			txtRecords: []string{
				"letsencrypt.org;ACCOUNTURI=http://letsencrypt.org:4000/acme/reg/1;accounturi=http://letsencrypt.org:4000/acme/reg/2",
			},
			wantProbType:   probs.MalformedProblem,
			wantDetailLike: `duplicate parameter "accounturi"`,
		},
		{
			name: "empty persistUntil value is malformed",
			txtRecords: []string{
				"letsencrypt.org;accounturi=http://letsencrypt.org:4000/acme/reg/1;persistUntil=",
			},
			wantProbType:   probs.MalformedProblem,
			wantDetailLike: `malformed persistUntil timestamp ""`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			va, _ := setup(nil, "", nil, &dnsPersistFakeDNS{
				records: map[string][]string{
					challHost: tc.txtRecords,
				},
				err: tc.dnsErr,
			})

			_, err := va.validateDNSPersist01(context.Background(), identifier.NewDNS(domain), accountURI, tc.wildcard)
			if tc.wantProbType == "" {
				test.AssertNotError(t, err, "expected validation to succeed")
				return
			}

			test.AssertError(t, err, "expected validation failure")
			prob := detailedError(err)
			test.AssertEquals(t, prob.Type, tc.wantProbType)
			test.Assert(t, strings.Contains(prob.Detail, tc.wantDetailLike), "expected error detail substring not found")
		})
	}
}

// dnsPersistMultiStringDNS is a fake DNS client that returns a single TXT
// record whose RDATA is split across multiple character-strings, as would
// occur when the record exceeds 255 bytes (RFC 1035, Section 3.3).
type dnsPersistMultiStringDNS struct {
	bdns.Client
	parts []string // each element is one character-string within a single TXT RR
}

func (d *dnsPersistMultiStringDNS) LookupTXT(_ context.Context, _ string) (*bdns.Result[*dns.TXT], string, error) {
	rr := &dns.TXT{Txt: d.parts}
	return &bdns.Result[*dns.TXT]{Final: []*dns.TXT{rr}}, "dnsPersistMultiStringDNS", nil
}

func TestDNSPersist01MultiStringTXTRecord(t *testing.T) {
	t.Parallel()

	accountURI := accountURIPrefixes[0] + "1"

	// Simulate a TXT record split across two character-strings, as a DNS
	// server would do for RDATA exceeding 255 bytes.
	va, _ := setup(nil, "", nil, &dnsPersistMultiStringDNS{
		parts: []string{
			"letsencrypt.org;accounturi=http://letsencrypt.org:4000",
			"/acme/reg/1",
		},
	})

	records, err := va.validateDNSPersist01(context.Background(), identifier.NewDNS("example.com"), accountURI, false)
	test.AssertNotError(t, err, "expected multi-string TXT record to validate")
	test.AssertEquals(t, len(records), 1)
	test.AssertEquals(t, records[0].Hostname, "example.com")
}

func TestDNSPersist01ValidationErrorsForNonDNSIdentifier(t *testing.T) {
	t.Parallel()

	va, _ := setup(nil, "", nil, &dnsPersistFakeDNS{})
	_, err := va.validateDNSPersist01(context.Background(), identifier.NewIP(netip.MustParseAddr("127.0.0.1")), accountURIPrefixes[0]+"1", false)
	test.AssertErrorIs(t, err, berrors.Malformed)
}
