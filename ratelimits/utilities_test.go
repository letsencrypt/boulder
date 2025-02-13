package ratelimits

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestFQDNsToETLDsPlusOne(t *testing.T) {
	domains := FQDNsToETLDsPlusOne([]string{})
	test.AssertEquals(t, len(domains), 0)

	domains = FQDNsToETLDsPlusOne([]string{"www.example.com", "example.com"})
	test.AssertDeepEquals(t, domains, []string{"example.com"})

	domains = FQDNsToETLDsPlusOne([]string{"www.example.com", "example.com", "www.example.co.uk"})
	test.AssertDeepEquals(t, domains, []string{"example.co.uk", "example.com"})

	domains = FQDNsToETLDsPlusOne([]string{"www.example.com", "example.com", "www.example.co.uk", "co.uk"})
	test.AssertDeepEquals(t, domains, []string{"co.uk", "example.co.uk", "example.com"})

	domains = FQDNsToETLDsPlusOne([]string{"foo.bar.baz.www.example.com", "baz.example.com"})
	test.AssertDeepEquals(t, domains, []string{"example.com"})

	domains = FQDNsToETLDsPlusOne([]string{"github.io", "foo.github.io", "bar.github.io"})
	test.AssertDeepEquals(t, domains, []string{"bar.github.io", "foo.github.io", "github.io"})
}
