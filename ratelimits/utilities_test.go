package ratelimits

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/test"
)

func TestFQDNsToETLDsPlusOne(t *testing.T) {
	domains := FQDNsToETLDsPlusOne(identifier.ACMEIdentifiers{})
	test.AssertEquals(t, len(domains), 0)

	domains = FQDNsToETLDsPlusOne(identifier.NewDNSSlice([]string{"www.example.com", "example.com"}))
	test.AssertDeepEquals(t, domains, []string{"example.com"})

	domains = FQDNsToETLDsPlusOne(identifier.NewDNSSlice([]string{"www.example.com", "example.com", "www.example.co.uk"}))
	test.AssertDeepEquals(t, domains, []string{"example.co.uk", "example.com"})

	domains = FQDNsToETLDsPlusOne(identifier.NewDNSSlice([]string{"www.example.com", "example.com", "www.example.co.uk", "co.uk"}))
	test.AssertDeepEquals(t, domains, []string{"co.uk", "example.co.uk", "example.com"})

	domains = FQDNsToETLDsPlusOne(identifier.NewDNSSlice([]string{"foo.bar.baz.www.example.com", "baz.example.com"}))
	test.AssertDeepEquals(t, domains, []string{"example.com"})

	domains = FQDNsToETLDsPlusOne(identifier.NewDNSSlice([]string{"github.io", "foo.github.io", "bar.github.io"}))
	test.AssertDeepEquals(t, domains, []string{"bar.github.io", "foo.github.io", "github.io"})

	domains = FQDNsToETLDsPlusOne(identifier.ACMEIdentifiers{identifier.NewDNS("example.com"), identifier.NewIP(netip.MustParseAddr("127.0.0.1"))})
	test.AssertDeepEquals(t, domains, []string{"example.com"})
}

func TestGuessIdentifiers(t *testing.T) {
	cases := []struct {
		name  string
		input []string
		want  identifier.ACMEIdentifiers
	}{
		{
			name:  "empty string",
			input: []string{""},
			want:  identifier.ACMEIdentifiers{identifier.NewDNS("")},
		},
		{
			name:  "one DNS name",
			input: []string{"example.com"},
			want:  identifier.ACMEIdentifiers{identifier.NewDNS("example.com")},
		},
		{
			name:  "one IPv4 address",
			input: []string{"127.0.0.1"},
			want:  identifier.ACMEIdentifiers{identifier.NewIP(netip.MustParseAddr("127.0.0.1"))},
		},
		{
			name:  "one IPv6 address",
			input: []string{"::1"},
			want:  identifier.ACMEIdentifiers{identifier.NewIP(netip.MustParseAddr("::1"))},
		},
		{
			name:  "DNS name, IPv4 address, IPv6 address, DNS name",
			input: []string{"example.com", "127.0.0.1", "::1", "signed.bad.horse"},
			want: identifier.ACMEIdentifiers{
				identifier.NewDNS("example.com"),
				identifier.NewIP(netip.MustParseAddr("127.0.0.1")),
				identifier.NewIP(netip.MustParseAddr("::1")),
				identifier.NewDNS("signed.bad.horse"),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := guessIdentifiers(tc.input)
			if !slices.Equal(got, tc.want) {
				t.Errorf("Got %#v, but want %#v", got, tc.want)
			}
		})
	}
}
