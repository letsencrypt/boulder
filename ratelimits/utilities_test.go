package ratelimits

import (
	"testing"

	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/test"
)

func TestIdentifiersToETLDsPlusOne(t *testing.T) {
	idents := IdentifiersToETLDsPlusOne([]identifier.ACMEIdentifier{})
	test.AssertEquals(t, len(idents), 0)

	idents = IdentifiersToETLDsPlusOne([]identifier.ACMEIdentifier{
		identifier.NewDNS("www.example.com"),
		identifier.NewDNS("example.com"),
	})
	test.AssertDeepEquals(t, idents, []identifier.ACMEIdentifier{
		identifier.NewDNS("example.com"),
	})

	idents = IdentifiersToETLDsPlusOne([]identifier.ACMEIdentifier{
		identifier.NewDNS("www.example.com"),
		identifier.NewDNS("example.com"),
		identifier.NewDNS("www.example.co.uk"),
	})
	test.AssertDeepEquals(t, idents, []identifier.ACMEIdentifier{
		identifier.NewDNS("example.co.uk"),
		identifier.NewDNS("example.com"),
	})

	idents = IdentifiersToETLDsPlusOne([]identifier.ACMEIdentifier{
		identifier.NewDNS("www.example.com"),
		identifier.NewDNS("example.com"),
		identifier.NewDNS("www.example.co.uk"),
		identifier.NewDNS("co.uk"),
	})
	test.AssertDeepEquals(t, idents, []identifier.ACMEIdentifier{
		identifier.NewDNS("co.uk"),
		identifier.NewDNS("example.co.uk"),
		identifier.NewDNS("example.com"),
	})

	idents = IdentifiersToETLDsPlusOne([]identifier.ACMEIdentifier{
		identifier.NewDNS("foo.bar.baz.www.example.com"),
		identifier.NewDNS("baz.example.com"),
	})
	test.AssertDeepEquals(t, idents, []identifier.ACMEIdentifier{
		identifier.NewDNS("example.com"),
	})

	idents = IdentifiersToETLDsPlusOne([]identifier.ACMEIdentifier{
		identifier.NewDNS("github.io"),
		identifier.NewDNS("foo.github.io"),
		identifier.NewDNS("bar.github.io"),
	})
	test.AssertDeepEquals(t, idents, []identifier.ACMEIdentifier{
		identifier.NewDNS("bar.github.io"),
		identifier.NewDNS("foo.github.io"),
		identifier.NewDNS("github.io"),
	})
}
