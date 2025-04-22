package ratelimits

import (
	"bytes"
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

func TestHashNames(t *testing.T) {
	// Test that it is deterministic
	h1 := hashNames([]string{"a"})
	h2 := hashNames([]string{"a"})
	test.AssertByteEquals(t, h1, h2)

	// Test that it differentiates
	h1 = hashNames([]string{"a"})
	h2 = hashNames([]string{"b"})
	test.Assert(t, !bytes.Equal(h1, h2), "Should have been different")

	// Test that it is not subject to ordering
	h1 = hashNames([]string{"a", "b"})
	h2 = hashNames([]string{"b", "a"})
	test.AssertByteEquals(t, h1, h2)

	// Test that it is not subject to case
	h1 = hashNames([]string{"a", "b"})
	h2 = hashNames([]string{"A", "B"})
	test.AssertByteEquals(t, h1, h2)

	// Test that it is not subject to duplication
	h1 = hashNames([]string{"a", "a"})
	h2 = hashNames([]string{"a"})
	test.AssertByteEquals(t, h1, h2)
}
