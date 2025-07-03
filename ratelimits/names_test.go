package ratelimits

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/test"
)

func TestNameIsValid(t *testing.T) {
	t.Parallel()
	type args struct {
		name Name
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "Unknown", args: args{name: Unknown}, want: false},
		{name: "9001", args: args{name: 9001}, want: false},
		{name: "NewRegistrationsPerIPAddress", args: args{name: NewRegistrationsPerIPAddress}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.args.name.isValid()
			test.AssertEquals(t, tt.want, got)
		})
	}
}

func TestValidateIdForName(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		limit Name
		desc  string
		id    string
		err   string
	}{
		{
			limit: NewRegistrationsPerIPAddress,
			desc:  "valid IPv4 address",
			id:    "64.112.117.1",
		},
		{
			limit: NewRegistrationsPerIPAddress,
			desc:  "reserved IPv4 address",
			id:    "10.0.0.1",
			err:   "in a reserved address block",
		},
		{
			limit: NewRegistrationsPerIPAddress,
			desc:  "valid IPv6 address",
			id:    "2602:80a:6000::42:42",
		},
		{
			limit: NewRegistrationsPerIPAddress,
			desc:  "IPv6 address in non-canonical form",
			id:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			err:   "must be in canonical form",
		},
		{
			limit: NewRegistrationsPerIPAddress,
			desc:  "empty string",
			id:    "",
			err:   "must be an IP address",
		},
		{
			limit: NewRegistrationsPerIPAddress,
			desc:  "one space",
			id:    " ",
			err:   "must be an IP address",
		},
		{
			limit: NewRegistrationsPerIPAddress,
			desc:  "invalid IPv4 address",
			id:    "10.0.0.9000",
			err:   "must be an IP address",
		},
		{
			limit: NewRegistrationsPerIPAddress,
			desc:  "invalid IPv6 address",
			id:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334:9000",
			err:   "must be an IP address",
		},
		{
			limit: NewRegistrationsPerIPv6Range,
			desc:  "valid IPv6 address range",
			id:    "2602:80a:6000::/48",
		},
		{
			limit: NewRegistrationsPerIPv6Range,
			desc:  "IPv6 address range in non-canonical form",
			id:    "2602:080a:6000::/48",
			err:   "must be in canonical form",
		},
		{
			limit: NewRegistrationsPerIPv6Range,
			desc:  "IPv6 address range with low bits set",
			id:    "2602:080a:6000::1/48",
			err:   "must be in canonical form",
		},
		{
			limit: NewRegistrationsPerIPv6Range,
			desc:  "invalid IPv6 CIDR range",
			id:    "2001:0db8:0000::/128",
			err:   "must be /48",
		},
		{
			limit: NewRegistrationsPerIPv6Range,
			desc:  "invalid IPv6 CIDR",
			id:    "2001:0db8:0000::/48/48",
			err:   "must be an IPv6 CIDR range",
		},
		{
			limit: NewRegistrationsPerIPv6Range,
			desc:  "IPv4 CIDR when we expect IPv6 CIDR range",
			id:    "10.0.0.0/16",
			err:   "must be /48",
		},
		{
			limit: NewRegistrationsPerIPv6Range,
			desc:  "IPv4 CIDR with invalid long mask",
			id:    "10.0.0.0/48",
			err:   "must be an IPv6 CIDR range",
		},
		{
			limit: NewOrdersPerAccount,
			desc:  "valid regId",
			id:    "1234567890",
		},
		{
			limit: NewOrdersPerAccount,
			desc:  "invalid regId",
			id:    "lol",
			err:   "must be an ACME registration Id",
		},
		{
			limit: FailedAuthorizationsPerDomainPerAccount,
			desc:  "transaction: valid regId and domain",
			id:    "12345:example.com",
		},
		{
			limit: FailedAuthorizationsPerDomainPerAccount,
			desc:  "transaction: invalid regId",
			id:    "12ea5:example.com",
			err:   "invalid regId",
		},
		{
			limit: FailedAuthorizationsPerDomainPerAccount,
			desc:  "transaction: invalid domain",
			id:    "12345:examplecom",
			err:   "name needs at least one dot",
		},
		{
			limit: FailedAuthorizationsPerDomainPerAccount,
			desc:  "override: valid regId",
			id:    "12345",
		},
		{
			limit: FailedAuthorizationsPerDomainPerAccount,
			desc:  "override: invalid regId",
			id:    "12ea5",
			err:   "invalid regId",
		},
		{
			limit: FailedAuthorizationsForPausingPerDomainPerAccount,
			desc:  "transaction: valid regId and domain",
			id:    "12345:example.com",
		},
		{
			limit: FailedAuthorizationsForPausingPerDomainPerAccount,
			desc:  "transaction: invalid regId",
			id:    "12ea5:example.com",
			err:   "invalid regId",
		},
		{
			limit: FailedAuthorizationsForPausingPerDomainPerAccount,
			desc:  "transaction: invalid domain",
			id:    "12345:examplecom",
			err:   "name needs at least one dot",
		},
		{
			limit: FailedAuthorizationsForPausingPerDomainPerAccount,
			desc:  "override: valid regId",
			id:    "12345",
		},
		{
			limit: FailedAuthorizationsForPausingPerDomainPerAccount,
			desc:  "override: invalid regId",
			id:    "12ea5",
			err:   "invalid regId",
		},
		{
			limit: CertificatesPerDomainPerAccount,
			desc:  "transaction: valid regId and domain",
			id:    "12345:example.com",
		},
		{
			limit: CertificatesPerDomainPerAccount,
			desc:  "transaction: invalid regId",
			id:    "12ea5:example.com",
			err:   "invalid regId",
		},
		{
			limit: CertificatesPerDomainPerAccount,
			desc:  "transaction: invalid domain",
			id:    "12345:examplecom",
			err:   "name needs at least one dot",
		},
		{
			limit: CertificatesPerDomainPerAccount,
			desc:  "override: valid regId",
			id:    "12345",
		},
		{
			limit: CertificatesPerDomainPerAccount,
			desc:  "override: invalid regId",
			id:    "12ea5",
			err:   "invalid regId",
		},
		{
			limit: CertificatesPerDomain,
			desc:  "valid domain",
			id:    "example.com",
		},
		{
			limit: CertificatesPerDomain,
			desc:  "valid IPv4 address",
			id:    "64.112.117.1",
		},
		{
			limit: CertificatesPerDomain,
			desc:  "valid IPv6 address",
			id:    "2602:80a:6000::",
		},
		{
			limit: CertificatesPerDomain,
			desc:  "IPv6 address with subnet",
			id:    "2602:80a:6000::/64",
			err:   "nor an IP address",
		},
		{
			limit: CertificatesPerDomain,
			desc:  "malformed domain",
			id:    "example:.com",
			err:   "name contains an invalid character",
		},
		{
			limit: CertificatesPerDomain,
			desc:  "empty domain",
			id:    "",
			err:   "Identifier value (name) is empty",
		},
		{
			limit: CertificatesPerFQDNSet,
			desc:  "valid fqdnSet containing a single domain",
			id:    "example.com",
		},
		{
			limit: CertificatesPerFQDNSet,
			desc:  "valid fqdnSet containing a single IPv4 address",
			id:    "64.112.117.1",
		},
		{
			limit: CertificatesPerFQDNSet,
			desc:  "valid fqdnSet containing a single IPv6 address",
			id:    "2602:80a:6000::1",
		},
		{
			limit: CertificatesPerFQDNSet,
			desc:  "valid fqdnSet containing multiple domains",
			id:    "example.com,example.org",
		},
		{
			limit: CertificatesPerFQDNSet,
			desc:  "valid fqdnSet containing multiple domains and IPs",
			id:    "2602:80a:6000::1,64.112.117.1,example.com,example.org",
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s/%s", tc.limit, tc.desc), func(t *testing.T) {
			t.Parallel()
			err := validateIdForName(tc.limit, tc.id)
			if tc.err != "" {
				test.AssertError(t, err, "should have failed")
				test.AssertContains(t, err.Error(), tc.err)
			} else {
				test.AssertNotError(t, err, "should have succeeded")
			}
		})
	}
}

func TestBuildBucketKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              Name
		desc              string
		regId             int64
		singleIdent       identifier.ACMEIdentifier
		setOfIdents       identifier.ACMEIdentifiers
		subscriberIP      netip.Addr
		expectErrContains string
		outputTest        func(t *testing.T, key string)
	}{
		// NewRegistrationsPerIPAddress
		{
			name:         NewRegistrationsPerIPAddress,
			desc:         "valid subscriber IPv4 address",
			subscriberIP: netip.MustParseAddr("1.2.3.4"),
			outputTest: func(t *testing.T, key string) {
				test.AssertEquals(t, fmt.Sprintf("%d:1.2.3.4", NewRegistrationsPerIPAddress), key)
			},
		},
		{
			name:         NewRegistrationsPerIPAddress,
			desc:         "valid subscriber IPv6 address",
			subscriberIP: netip.MustParseAddr("2001:db8::1"),
			outputTest: func(t *testing.T, key string) {
				test.AssertEquals(t, fmt.Sprintf("%d:2001:db8::1", NewRegistrationsPerIPAddress), key)
			},
		},
		// NewRegistrationsPerIPv6Range
		{
			name:         NewRegistrationsPerIPv6Range,
			desc:         "valid subscriber IPv6 address",
			subscriberIP: netip.MustParseAddr("2001:db8:abcd:12::1"),
			outputTest: func(t *testing.T, key string) {
				test.AssertEquals(t, fmt.Sprintf("%d:2001:db8:abcd::/48", NewRegistrationsPerIPv6Range), key)
			},
		},
		{
			name:              NewRegistrationsPerIPv6Range,
			desc:              "subscriber IPv4 given for subscriber IPv6 range limit",
			subscriberIP:      netip.MustParseAddr("1.2.3.4"),
			expectErrContains: "requires an IPv6 address",
		},

		// NewOrdersPerAccount
		{
			name:  NewOrdersPerAccount,
			desc:  "valid registration ID",
			regId: 1337,
			outputTest: func(t *testing.T, key string) {
				test.AssertEquals(t, fmt.Sprintf("%d:1337", NewOrdersPerAccount), key)
			},
		},
		{
			name:              NewOrdersPerAccount,
			desc:              "registration ID missing",
			expectErrContains: "regId is required",
		},

		// CertificatesPerDomain
		{
			name:        CertificatesPerDomain,
			desc:        "DNS identifier to eTLD+1",
			singleIdent: identifier.NewDNS("www.example.com"),
			outputTest: func(t *testing.T, key string) {
				test.AssertEquals(t, fmt.Sprintf("%d:example.com", CertificatesPerDomain), key)
			},
		},
		{
			name:        CertificatesPerDomain,
			desc:        "valid IPv4 address used as identifier",
			singleIdent: identifier.NewIP(netip.MustParseAddr("5.6.7.8")),
			outputTest: func(t *testing.T, key string) {
				test.AssertEquals(t, fmt.Sprintf("%d:5.6.7.8/32", CertificatesPerDomain), key)
			},
		},
		{
			name:        CertificatesPerDomain,
			desc:        "valid IPv6 address used as identifier",
			singleIdent: identifier.NewIP(netip.MustParseAddr("2001:db8::1")),
			outputTest: func(t *testing.T, key string) {
				test.AssertEquals(t, fmt.Sprintf("%d:2001:db8::/64", CertificatesPerDomain), key)
			},
		},
		{
			name:              CertificatesPerDomain,
			desc:              "identifier missing",
			expectErrContains: "singleIdent is required",
		},

		// CertificatesPerFQDNSet
		{
			name:        CertificatesPerFQDNSet,
			desc:        "multiple valid DNS identifiers",
			setOfIdents: identifier.NewDNSSlice([]string{"example.com", "example.org"}),
			outputTest: func(t *testing.T, key string) {
				if !strings.HasPrefix(key, fmt.Sprintf("%d:", CertificatesPerFQDNSet)) {
					t.Errorf("expected key to start with %d: got %s", CertificatesPerFQDNSet, key)
				}
			},
		},
		{
			name:        CertificatesPerFQDNSet,
			desc:        "multiple valid DNS and IP identifiers",
			setOfIdents: identifier.ACMEIdentifiers{identifier.NewDNS("example.net"), identifier.NewIP(netip.MustParseAddr("5.6.7.8")), identifier.NewIP(netip.MustParseAddr("2001:db8::1"))},
			outputTest: func(t *testing.T, key string) {
				if !strings.HasPrefix(key, fmt.Sprintf("%d:", CertificatesPerFQDNSet)) {
					t.Errorf("expected key to start with %d: got %s", CertificatesPerFQDNSet, key)
				}
			},
		},
		{
			name:              CertificatesPerFQDNSet,
			desc:              "identifiers missing",
			expectErrContains: "setOfIdents is required",
		},

		// CertificatesPerDomainPerAccount
		{
			name:  CertificatesPerDomainPerAccount,
			desc:  "only registration ID",
			regId: 1337,
			outputTest: func(t *testing.T, key string) {
				test.AssertEquals(t, fmt.Sprintf("%d:1337", CertificatesPerDomainPerAccount), key)
			},
		},
		{
			name:        CertificatesPerDomainPerAccount,
			desc:        "registration ID and single DNS identifier provided",
			regId:       1337,
			singleIdent: identifier.NewDNS("example.com"),
			outputTest: func(t *testing.T, key string) {
				test.AssertEquals(t, fmt.Sprintf("%d:1337:example.com", CertificatesPerDomainPerAccount), key)
			},
		},
		{
			name:              CertificatesPerDomainPerAccount,
			desc:              "single DNS identifier provided without registration ID",
			singleIdent:       identifier.NewDNS("example.com"),
			expectErrContains: "regId is required",
		},

		// FailedAuthorizationsPerDomainPerAccount
		{
			name:        FailedAuthorizationsPerDomainPerAccount,
			desc:        "registration ID and single DNS identifier",
			regId:       1337,
			singleIdent: identifier.NewDNS("example.com"),
			outputTest: func(t *testing.T, key string) {
				test.AssertEquals(t, fmt.Sprintf("%d:1337:example.com", FailedAuthorizationsPerDomainPerAccount), key)
			},
		},
		{
			name:  FailedAuthorizationsPerDomainPerAccount,
			desc:  "only registration ID",
			regId: 1337,
			outputTest: func(t *testing.T, key string) {
				test.AssertEquals(t, fmt.Sprintf("%d:1337", FailedAuthorizationsPerDomainPerAccount), key)
			},
		},

		// FailedAuthorizationsForPausingPerDomainPerAccount
		{
			name:        FailedAuthorizationsForPausingPerDomainPerAccount,
			desc:        "registration ID and single DNS identifier",
			regId:       1337,
			singleIdent: identifier.NewDNS("example.com"),
			outputTest: func(t *testing.T, key string) {
				test.AssertEquals(t, fmt.Sprintf("%d:1337:example.com", FailedAuthorizationsForPausingPerDomainPerAccount), key)
			},
		},
		{
			name:  FailedAuthorizationsForPausingPerDomainPerAccount,
			desc:  "only registration ID",
			regId: 1337,
			outputTest: func(t *testing.T, key string) {
				test.AssertEquals(t, fmt.Sprintf("%d:1337", FailedAuthorizationsForPausingPerDomainPerAccount), key)
			},
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s/%s", tc.name, tc.desc), func(t *testing.T) {
			t.Parallel()

			key, err := BuildBucketKey(tc.name, tc.regId, tc.singleIdent, tc.setOfIdents, tc.subscriberIP)
			if tc.expectErrContains != "" {
				test.AssertError(t, err, "expected error")
				test.AssertContains(t, err.Error(), tc.expectErrContains)
				return
			}
			test.AssertNotError(t, err, "unexpected error")
			tc.outputTest(t, key)
		})
	}
}
