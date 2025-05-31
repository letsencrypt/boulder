package ratelimits

import (
	"net/netip"
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
