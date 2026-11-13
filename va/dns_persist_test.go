package va

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/miekg/dns"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"
)

func TestParseDNSPersistRecord(t *testing.T) {
	t.Parallel()

	accountURI := accountURIPrefixes[0] + "1"

	testCases := []struct {
		name               string
		record             string
		expectIssuer       string
		expectAccountURI   string
		expectPolicy       string
		expectPersistUntil time.Time
		expectErrContains  string
	}{
		{
			name:             "Valid record",
			record:           "letsencrypt.org;accounturi=" + accountURI,
			expectIssuer:     "letsencrypt.org",
			expectAccountURI: accountURI,
		},
		{
			name:             "Issuer-domain-name is uppercase + trailing dot",
			record:           "LETSENCRYPT.ORG.;accounturi=" + accountURI,
			expectIssuer:     "letsencrypt.org",
			expectAccountURI: accountURI,
		},
		{
			name:             "Non-matching issuer-domain-name is parsed",
			record:           "other.example;accounturi=" + accountURI,
			expectIssuer:     "other.example",
			expectAccountURI: accountURI,
		},
		{
			name:              "Missing issuer-domain-name is malformed",
			record:            ";accounturi=" + accountURI,
			expectErrContains: "empty issuer-domain-name",
		},
		{
			name:               "All known fields with heavy whitespace",
			record:             "   letsencrypt.org   ;   accounturi   =   " + accountURI + "   ;   policy   =   wildcard   ;   persistUntil   =   4102444800   ",
			expectIssuer:       "letsencrypt.org",
			expectAccountURI:   accountURI,
			expectPolicy:       "wildcard",
			expectPersistUntil: time.Unix(4102444800, 0).UTC(),
		},
		{
			name:             "Unknown tags are ignored",
			record:           "letsencrypt.org;accounturi=" + accountURI + ";bad tag=value;\nweird=\\x01337",
			expectIssuer:     "letsencrypt.org",
			expectAccountURI: accountURI,
		},
		{
			name:             "Duplicate unknown parameter is ignored",
			record:           "letsencrypt.org;accounturi=" + accountURI + ";foo=bar;foo=baz",
			expectIssuer:     "letsencrypt.org",
			expectAccountURI: accountURI,
		},
		{
			name:              "Missing equals is malformed",
			record:            "letsencrypt.org;accounturi=" + accountURI + ";invalidparam",
			expectIssuer:      "letsencrypt.org",
			expectErrContains: `malformed parameter "invalidparam" should be tag=value pair`,
		},
		{
			name:              "Empty tag is malformed",
			record:            "letsencrypt.org;accounturi=" + accountURI + ";=abc",
			expectIssuer:      "letsencrypt.org",
			expectErrContains: `malformed parameter "=abc", empty tag`,
		},
		{
			name:              "Empty accounturi value is malformed",
			record:            "letsencrypt.org;accounturi=",
			expectIssuer:      "letsencrypt.org",
			expectErrContains: "empty value provided for mandatory accounturi",
		},
		{
			name:              "Missing accounturi parameter is malformed",
			record:            "letsencrypt.org;policy=wildcard",
			expectIssuer:      "letsencrypt.org",
			expectErrContains: "missing mandatory accounturi parameter",
		},
		{
			name:              "Invalid value character is malformed",
			record:            "letsencrypt.org;accounturi=" + accountURI + ";policy=wild card",
			expectIssuer:      "letsencrypt.org",
			expectErrContains: `malformed value "wild card" for tag "policy"`,
		},
		{
			name:              "Non-numeric persistUntil is malformed",
			record:            "letsencrypt.org;accounturi=" + accountURI + ";persistUntil=not-a-unix-timestamp",
			expectIssuer:      "letsencrypt.org",
			expectErrContains: `malformed persistUntil timestamp "not-a-unix-timestamp"`,
		},
		{
			name:              "Trailing semicolon is malformed",
			record:            "letsencrypt.org;accounturi=" + accountURI + ";",
			expectIssuer:      "letsencrypt.org",
			expectErrContains: "empty parameter or trailing semicolon provided",
		},
		{
			name:              "Duplicate parameter detection is case-insensitive",
			record:            "letsencrypt.org;ACCOUNTURI=" + accountURI + ";accounturi=other",
			expectIssuer:      "letsencrypt.org",
			expectErrContains: `duplicate parameter "accounturi"`,
		},
		{
			name:              "Empty persistUntil value is malformed",
			record:            "letsencrypt.org;accounturi=" + accountURI + ";persistUntil=",
			expectIssuer:      "letsencrypt.org",
			expectErrContains: `malformed persistUntil timestamp ""`,
		},
		{
			name:             "Case-insensitive policy tag",
			record:           "letsencrypt.org;accounturi=" + accountURI + ";pOlIcY=wildcard",
			expectIssuer:     "letsencrypt.org",
			expectAccountURI: accountURI,
			expectPolicy:     "wildcard",
		},
		{
			name:              "Non-matching record with duplicate parameter returns error",
			record:            "other.example;accounturi=" + accountURI + ";accounturi=other",
			expectIssuer:      "other.example",
			expectErrContains: `duplicate parameter "accounturi"`,
		},
		{
			name:              "Issuer only without parameters is malformed",
			record:            "letsencrypt.org",
			expectIssuer:      "letsencrypt.org",
			expectErrContains: "missing mandatory accounturi parameter",
		},
		{
			name:               "Valid persistUntil is parsed",
			record:             "letsencrypt.org;accounturi=" + accountURI + ";persistUntil=1721952000",
			expectIssuer:       "letsencrypt.org",
			expectAccountURI:   accountURI,
			expectPersistUntil: time.Unix(1721952000, 0).UTC(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			receivedIssuer, params, err := parseDNSPersistRecord(tc.record)
			if tc.expectErrContains != "" {
				test.AssertError(t, err, "expected parse error")
				test.AssertContains(t, err.Error(), tc.expectErrContains)
				test.AssertEquals(t, receivedIssuer, tc.expectIssuer)
				return
			}
			test.AssertNotError(t, err, "unexpected parse error")
			test.Assert(t, params != nil, "expected non-nil params")
			test.AssertEquals(t, receivedIssuer, tc.expectIssuer)
			test.AssertEquals(t, params.accountURI, tc.expectAccountURI)
			if tc.expectPolicy != "" {
				test.AssertEquals(t, params.policy, tc.expectPolicy)
			}
			if !tc.expectPersistUntil.IsZero() {
				test.AssertEquals(t, params.persistUntil, tc.expectPersistUntil)
			}
		})
	}
}

func TestCheckDNSPersistRecord(t *testing.T) {
	t.Parallel()

	accountURI := accountHashPrefix + "sha-256/5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw"
	now := time.Now().UTC()

	testCases := []struct {
		name              string
		params            *dnsPersistIssueValueParams
		accountURI        string
		wildcardName      bool
		validatedAt       time.Time
		exceptErr         error
		expectErrContains string
	}{
		{
			name:        "Valid non-wildcard",
			params:      &dnsPersistIssueValueParams{accountURI: accountURI},
			accountURI:  accountURI,
			validatedAt: now,
		},
		{
			name:         "Valid wildcard",
			params:       &dnsPersistIssueValueParams{accountURI: accountURI, policy: "wildcard"},
			accountURI:   accountURI,
			wildcardName: true,
			validatedAt:  now,
		},
		{
			name:         "Wildcard accepts case-insensitive policy",
			params:       &dnsPersistIssueValueParams{accountURI: accountURI, policy: "wIlDcArD"},
			accountURI:   accountURI,
			wildcardName: true,
			validatedAt:  now,
		},
		{
			name:        "Policy other than wildcard is treated as absent for non-wildcard",
			params:      &dnsPersistIssueValueParams{accountURI: accountURI, policy: "notwildcard"},
			accountURI:  accountURI,
			validatedAt: now,
		},
		{
			name: "Valid with future persistUntil",
			params: &dnsPersistIssueValueParams{
				accountURI:   accountURI,
				persistUntil: now.Add(time.Hour),
			},
			accountURI:  accountURI,
			validatedAt: now,
		},
		{
			name:              "Accounturi mismatch",
			params:            &dnsPersistIssueValueParams{accountURI: accountHashPrefix + "sha-256/NpDnSwUthQK8zCgFdefYxAdAVPnygMLbs9US6oO-5ug"},
			accountURI:        accountURI,
			validatedAt:       now,
			exceptErr:         berrors.Unauthorized,
			expectErrContains: "accounturi mismatch",
		},
		{
			name:              "Accounturi which is an account URL",
			params:            &dnsPersistIssueValueParams{accountURI: accountURIPrefixes[0] + "1"},
			accountURI:        accountURI,
			validatedAt:       now,
			exceptErr:         berrors.Malformed,
			expectErrContains: "is not of the form",
		},
		{
			name:              "Accounturi with unsupported hash algorithm",
			params:            &dnsPersistIssueValueParams{accountURI: accountHashPrefix + "sha-384/5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw"},
			accountURI:        accountURI,
			validatedAt:       now,
			exceptErr:         berrors.Malformed,
			expectErrContains: "is not of the form",
		},
		{
			name:              "Accounturi with truncated hash value",
			params:            &dnsPersistIssueValueParams{accountURI: accountHashPrefix + "sha-256/5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk"},
			accountURI:        accountURI,
			validatedAt:       now,
			exceptErr:         berrors.Malformed,
			expectErrContains: "is not of the form",
		},
		{
			name:              "Accounturi with padded hash value",
			params:            &dnsPersistIssueValueParams{accountURI: accountHashPrefix + "sha-256/5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw="},
			accountURI:        accountURI,
			validatedAt:       now,
			exceptErr:         berrors.Malformed,
			expectErrContains: "is not of the form",
		},
		{
			name:              "Wildcard request with absent policy is unauthorized",
			params:            &dnsPersistIssueValueParams{accountURI: accountURI},
			accountURI:        accountURI,
			wildcardName:      true,
			validatedAt:       now,
			exceptErr:         berrors.Unauthorized,
			expectErrContains: `policy mismatch: expected "wildcard"`,
		},
		{
			name:              "Wildcard policy mismatch",
			params:            &dnsPersistIssueValueParams{accountURI: accountURI, policy: "notwildcard"},
			accountURI:        accountURI,
			wildcardName:      true,
			validatedAt:       now,
			exceptErr:         berrors.Unauthorized,
			expectErrContains: `policy mismatch: expected "wildcard"`,
		},
		{
			name: "Expired persistUntil",
			params: &dnsPersistIssueValueParams{
				accountURI:   accountURI,
				persistUntil: now.Add(-time.Hour),
			},
			accountURI:        accountURI,
			validatedAt:       now,
			exceptErr:         berrors.Unauthorized,
			expectErrContains: "validation time",
		},
		{
			name: "Negative persistUntil",
			params: &dnsPersistIssueValueParams{
				accountURI:   accountURI,
				persistUntil: time.Unix(-1, 0).UTC(),
			},
			accountURI:        accountURI,
			validatedAt:       now,
			exceptErr:         berrors.Unauthorized,
			expectErrContains: "validation time",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := checkDNSPersistRecord(tc.params, accountHashPrefix, []string{tc.accountURI}, tc.wildcardName, tc.validatedAt)
			if tc.exceptErr != nil {
				test.AssertError(t, err, "expected check error")
				test.AssertErrorIs(t, err, tc.exceptErr)
				test.AssertContains(t, err.Error(), tc.expectErrContains)
				return
			}
			test.AssertNotError(t, err, "unexpected check error")
		})
	}
}

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

func TestValidateDNSPersist01(t *testing.T) {
	t.Parallel()

	const (
		domain    = "example.com"
		challHost = "_validation-persist.example.com"
	)
	accountURI := accountHashPrefix + "sha-256/5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw"
	otherAccountURI := accountHashPrefix + "sha-256/NpDnSwUthQK8zCgFdefYxAdAVPnygMLbs9US6oO-5ug"

	testCases := []struct {
		name                 string
		txtRecords           []string
		wildcard             bool
		dnsErr               error
		expectPersistUntil   time.Time
		expectProbType       probs.ProblemType
		expectDetailContains string
	}{
		{
			name:                 "Lookup failure returns DNS problem",
			dnsErr:               errors.New("SERVFAIL"),
			expectProbType:       probs.DNSProblem,
			expectDetailContains: "Retrieving TXT records for DNS-PERSIST-01 challenge",
		},
		{
			name:                 "No TXT records found returns unauthorized",
			expectProbType:       probs.UnauthorizedProblem,
			expectDetailContains: "No TXT record found for DNS-PERSIST-01 challenge",
		},
		{
			name: "Matching malformed and matching valid record succeeds",
			txtRecords: []string{
				"letsencrypt.org;accounturi=" + accountURI + ";accounturi=other",
				"letsencrypt.org;accounturi=" + accountURI,
			},
		},
		{
			name: "Matching unauthorized and matching valid record succeeds",
			txtRecords: []string{
				"letsencrypt.org;accounturi=" + otherAccountURI,
				"letsencrypt.org;accounturi=" + accountURI,
			},
		},
		{
			name: "Valid record with persistUntil returns it",
			txtRecords: []string{
				"letsencrypt.org;accounturi=" + accountURI + ";persistUntil=4102444800",
			},
			expectPersistUntil: time.Unix(4102444800, 0).UTC(),
		},
		{
			name: "Valid wildcard record succeeds",
			txtRecords: []string{
				"letsencrypt.org;accounturi=" + accountURI + ";policy=wildcard",
			},
			wildcard: true,
		},
		{
			name: "Only matching malformed record returns malformed",
			txtRecords: []string{
				"letsencrypt.org;accounturi=" + accountURI + ";accounturi=other",
			},
			expectProbType:       probs.MalformedProblem,
			expectDetailContains: "duplicate parameter",
		},
		{
			name: "Only matching unauthorized record returns unauthorized",
			txtRecords: []string{
				"letsencrypt.org;accounturi=" + otherAccountURI,
			},
			expectProbType:       probs.UnauthorizedProblem,
			expectDetailContains: "accounturi mismatch",
		},
		{
			name: "Accounturi which is an account URL returns malformed",
			txtRecords: []string{
				"letsencrypt.org;accounturi=" + accountURIPrefixes[0] + "1",
			},
			expectProbType:       probs.MalformedProblem,
			expectDetailContains: "is not of the form",
		},
		{
			name: "Missing accounturi returns malformed",
			txtRecords: []string{
				"letsencrypt.org;policy=wildcard",
			},
			expectProbType:       probs.MalformedProblem,
			expectDetailContains: "missing mandatory accounturi parameter",
		},
		{
			name: "Expired persistUntil returns unauthorized",
			txtRecords: []string{
				"letsencrypt.org;accounturi=" + accountURI + ";persistUntil=0",
			},
			expectProbType:       probs.UnauthorizedProblem,
			expectDetailContains: "validation time",
		},
		{
			name: "Non-matching issuer with no valid records returns unauthorized",
			txtRecords: []string{
				"other.example;accounturi=" + accountURI,
			},
			expectProbType:       probs.UnauthorizedProblem,
			expectDetailContains: "No valid TXT record found",
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
			fc := clock.NewFake()
			fc.Set(time.Now())
			va.clk = fc

			_, params, err := va.validateDNSPersist01(context.Background(), identifier.NewDNS(domain), []string{accountURI}, tc.wildcard)
			if tc.expectProbType == "" {
				test.AssertNotError(t, err, "expected validation to succeed")
				test.AssertEquals(t, params.accountURI, accountURI)
				test.AssertEquals(t, params.persistUntil, tc.expectPersistUntil)
				return
			}

			test.AssertError(t, err, "expected validation failure")
			prob := detailedError(err)
			test.AssertEquals(t, prob.Type, tc.expectProbType)
			test.AssertContains(t, prob.Detail, tc.expectDetailContains)
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

	// Simulate a TXT record split across two character-strings, as a DNS
	// server would do for RDATA exceeding 255 bytes.
	va, _ := setup(nil, "", nil, &dnsPersistMultiStringDNS{
		parts: []string{
			"letsencrypt.org;accounturi=http://letsencrypt.org:4000",
			"/acme/acct-hash/sha-256/5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw",
		},
	})

	records, _, err := va.validateDNSPersist01(context.Background(), identifier.NewDNS("example.com"), []string{accountHashPrefix + "sha-256/5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw"}, false)
	test.AssertNotError(t, err, "expected multi-string TXT record to validate")
	test.AssertEquals(t, len(records), 1)
	test.AssertEquals(t, records[0].Hostname, "example.com")
}

func TestDNSPersist01ValidationErrorsForNonDNSIdentifier(t *testing.T) {
	t.Parallel()

	va, _ := setup(nil, "", nil, &dnsPersistFakeDNS{})
	_, _, err := va.validateDNSPersist01(context.Background(), identifier.NewIP(netip.MustParseAddr("127.0.0.1")), []string{accountHashPrefix + "sha-256/5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw"}, false)
	test.AssertErrorIs(t, err, berrors.Malformed)
}

// TestDoDCVDNSPersist01HashedAccountURI uses the hash inputs and outputs from
// draft-ietf-acme-dns-persist-02 section 10.2, under our own hash prefix.
func TestDoDCVDNSPersist01HashedAccountURI(t *testing.T) {
	const (
		domainAccountURI   = accountHashPrefix + "sha-256/5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw"
		wildcardAccountURI = accountHashPrefix + "sha-256/NpDnSwUthQK8zCgFdefYxAdAVPnygMLbs9US6oO-5ug"
	)
	thumbprint, err := base64.RawURLEncoding.DecodeString("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
	test.AssertNotError(t, err, "decoding thumbprint")
	otherThumbprint := make([]byte, 32)

	testCases := []struct {
		name           string
		ident          identifier.ACMEIdentifier
		txtRecord      string
		thumbprints    [][]byte
		expectProbType probs.ProblemType
	}{
		{
			name:        "Hash over the domain and current key",
			ident:       identifier.NewDNS("example.com"),
			txtRecord:   "letsencrypt.org;accounturi=" + domainAccountURI,
			thumbprints: [][]byte{thumbprint},
		},
		{
			name:        "Hash over the domain-omitted form",
			ident:       identifier.NewDNS("example.com"),
			txtRecord:   "letsencrypt.org;accounturi=" + wildcardAccountURI,
			thumbprints: [][]byte{thumbprint},
		},
		{
			name:        "Hash over the domain and a prior key",
			ident:       identifier.NewDNS("example.com"),
			txtRecord:   "letsencrypt.org;accounturi=" + domainAccountURI,
			thumbprints: [][]byte{otherThumbprint, thumbprint},
		},
		{
			name:        "Hash over the base domain of a wildcard identifier",
			ident:       identifier.NewDNS("*.example.com"),
			txtRecord:   "letsencrypt.org;accounturi=" + domainAccountURI + ";policy=wildcard",
			thumbprints: [][]byte{thumbprint},
		},
		{
			name:           "Hash over a key the account has not used",
			ident:          identifier.NewDNS("example.com"),
			txtRecord:      "letsencrypt.org;accounturi=" + domainAccountURI,
			thumbprints:    [][]byte{otherThumbprint},
			expectProbType: probs.UnauthorizedProblem,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			va, _ := setup(nil, "", nil, &dnsPersistFakeDNS{
				records: map[string][]string{
					"_validation-persist.example.com": {tc.txtRecord},
				},
			})
			va.accountURIPrefixes = []string{"https://ca.example/acct/"}
			features.Set(features.Config{DNSPersist01Enabled: true})
			defer features.Reset()

			req := createValidationRequest(tc.ident, core.ChallengeTypeDNSPersist01)
			req.Authz.RegID = 123
			req.AccountKeyThumbprints = tc.thumbprints

			res, err := va.DoDCV(context.Background(), req)
			test.AssertNotError(t, err, "DoDCV failed")
			if tc.expectProbType == "" {
				test.Assert(t, res.Problem == nil, "expected validation to succeed")
				return
			}
			test.AssertEquals(t, res.Problem.ProblemType, string(tc.expectProbType))
		})
	}
}

func TestDoDCVDNSPersist01RemotesObserveSameAccountURI(t *testing.T) {
	const (
		challHost          = "_validation-persist.example.com"
		domainAccountURI   = accountHashPrefix + "sha-256/5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw"
		wildcardAccountURI = accountHashPrefix + "sha-256/NpDnSwUthQK8zCgFdefYxAdAVPnygMLbs9US6oO-5ug"
		persistUntil       = 4102444800
	)
	thumbprint, err := base64.RawURLEncoding.DecodeString("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
	test.AssertNotError(t, err, "decoding thumbprint")

	testCases := []struct {
		name           string
		remoteRecord   string
		expectProbType probs.ProblemType
	}{
		{
			name:         "Remotes observe the record the primary validated",
			remoteRecord: "letsencrypt.org;accounturi=" + domainAccountURI,
		},
		{
			name:           "Remotes observe a different record for the same account",
			remoteRecord:   "letsencrypt.org;accounturi=" + wildcardAccountURI,
			expectProbType: probs.UnauthorizedProblem,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var remotes []remoteConf
			for _, rir := range []string{arin, ripe, apnic, lacnic} {
				remotes = append(remotes, remoteConf{
					rir: rir,
					dns: &dnsPersistFakeDNS{records: map[string][]string{challHost: {tc.remoteRecord}}},
				})
			}
			va, _ := setupWithRemotes(nil, "", remotes, &dnsPersistFakeDNS{
				records: map[string][]string{
					challHost: {"letsencrypt.org;accounturi=" + domainAccountURI + ";persistUntil=4102444800"},
				},
			})
			va.accountURIPrefixes = []string{"https://ca.example/acct/"}
			features.Set(features.Config{DNSPersist01Enabled: true})
			defer features.Reset()

			req := createValidationRequest(identifier.NewDNS("example.com"), core.ChallengeTypeDNSPersist01)
			req.Authz.RegID = 123
			req.AccountKeyThumbprints = [][]byte{thumbprint}

			res, err := va.DoDCV(context.Background(), req)
			test.AssertNotError(t, err, "DoDCV failed")
			if tc.expectProbType == "" {
				test.Assert(t, res.Problem == nil, "expected validation to succeed")
				test.AssertEquals(t, res.PersistUntil.AsTime(), time.Unix(persistUntil, 0).UTC())
				return
			}
			test.AssertEquals(t, res.Problem.ProblemType, string(tc.expectProbType))
		})
	}
}
