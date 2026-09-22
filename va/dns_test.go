package va

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/miekg/dns"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"
)

type txtFakeDNS struct {
	bdns.Client
}

func (c *txtFakeDNS) LookupTXT(_ context.Context, hostname string) (*bdns.Result[*dns.TXT], string, error) {
	// Use the example account-specific label prefix derived from
	// "https://example.com/acme/acct/ExampleAccount"
	const accountLabelPrefix = "_ujmmovf2vn55tgye._acme-challenge"

	var wrapTXT = func(txts ...string) (*bdns.Result[*dns.TXT], string, error) {
		var rrs []*dns.TXT
		for _, txt := range txts {
			rrs = append(rrs, &dns.TXT{Txt: []string{txt}})
		}
		return &bdns.Result[*dns.TXT]{Final: rrs}, "txtFakeDNS", nil
	}

	if hostname == accountLabelPrefix+".servfail.com" {
		// Mirror dns-01 servfail behaviour
		return nil, "txtFakeDNS", fmt.Errorf("SERVFAIL")
	}
	if hostname == accountLabelPrefix+".good-dns01.com" {
		// Mirror dns-01 good record
		// base64(sha256("LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
		//               + "." + "9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI"))
		return wrapTXT("LPsIwTo7o8BoG0-vjCyGQGBWSVIPxI-i_X336eUOQZo")
	}
	if hostname == accountLabelPrefix+".wrong-dns01.com" {
		// Mirror dns-01 wrong record
		return wrapTXT("a")
	}
	if hostname == accountLabelPrefix+".wrong-many-dns01.com" {
		// Mirror dns-01 wrong-many record
		return wrapTXT("a", "b", "c", "d", "e")
	}
	if hostname == accountLabelPrefix+".long-dns01.com" {
		// Mirror dns-01 long record
		return wrapTXT("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	}
	if hostname == accountLabelPrefix+".no-authority-dns01.com" {
		// Mirror dns-01 no-authority good record
		// base64(sha256("LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
		//               + "." + "9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI"))
		return wrapTXT("LPsIwTo7o8BoG0-vjCyGQGBWSVIPxI-i_X336eUOQZo")
	}
	if hostname == accountLabelPrefix+".empty-txts.com" {
		// Mirror dns-01 zero TXT records
		return wrapTXT()
	}

	if hostname == "_acme-challenge.servfail.com" {
		return nil, "txtFakeDNS", fmt.Errorf("SERVFAIL")
	}
	if hostname == "_acme-challenge.good-dns01.com" {
		// base64(sha256("LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
		//               + "." + "9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI"))
		// expected token + test account jwk thumbprint
		return wrapTXT("LPsIwTo7o8BoG0-vjCyGQGBWSVIPxI-i_X336eUOQZo")
	}
	if hostname == "_acme-challenge.wrong-dns01.com" {
		return wrapTXT("a")
	}
	if hostname == "_acme-challenge.wrong-many-dns01.com" {
		return wrapTXT("a", "b", "c", "d", "e")
	}
	if hostname == "_acme-challenge.long-dns01.com" {
		return wrapTXT("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	}
	if hostname == "_acme-challenge.no-authority-dns01.com" {
		// base64(sha256("LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
		//               + "." + "9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI"))
		// expected token + test account jwk thumbprint
		return wrapTXT("LPsIwTo7o8BoG0-vjCyGQGBWSVIPxI-i_X336eUOQZo")
	}
	// empty-txts.com always returns zero TXT records
	if hostname == "_acme-challenge.empty-txts.com" {
		return wrapTXT()
	}

	// Default fallback
	return wrapTXT("hostname")
}

func TestDNS01ValidationWrong(t *testing.T) {
	va, _ := setup(nil, "", nil, &txtFakeDNS{})
	_, err := va.validateDNS01(context.Background(), identifier.NewDNS("wrong-dns01.com"), expectedKeyAuthorization)
	if err == nil {
		t.Fatalf("Successful DNS validation with wrong TXT record")
	}
	prob := detailedError(err)
	test.AssertEquals(t, prob.String(), "unauthorized :: Incorrect TXT record \"a\" found at _acme-challenge.wrong-dns01.com")
}

func TestDNS01ValidationWrongMany(t *testing.T) {
	va, _ := setup(nil, "", nil, &txtFakeDNS{})

	_, err := va.validateDNS01(context.Background(), identifier.NewDNS("wrong-many-dns01.com"), expectedKeyAuthorization)
	if err == nil {
		t.Fatalf("Successful DNS validation with wrong TXT record")
	}
	prob := detailedError(err)
	test.AssertEquals(t, prob.String(), "unauthorized :: Incorrect TXT record \"a\" (and 4 more) found at _acme-challenge.wrong-many-dns01.com")
}

func TestDNS01ValidationWrongLong(t *testing.T) {
	va, _ := setup(nil, "", nil, &txtFakeDNS{})

	_, err := va.validateDNS01(context.Background(), identifier.NewDNS("long-dns01.com"), expectedKeyAuthorization)
	if err == nil {
		t.Fatalf("Successful DNS validation with wrong TXT record")
	}
	prob := detailedError(err)
	test.AssertEquals(t, prob.String(), "unauthorized :: Incorrect TXT record \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...\" found at _acme-challenge.long-dns01.com")
}

func TestDNS01ValidationFailure(t *testing.T) {
	va, _ := setup(nil, "", nil, &txtFakeDNS{})

	_, err := va.validateDNS01(ctx, identifier.NewDNS("localhost"), expectedKeyAuthorization)
	prob := detailedError(err)

	test.AssertEquals(t, prob.Type, probs.UnauthorizedProblem)
}

func TestDNS01ValidationIP(t *testing.T) {
	va, _ := setup(nil, "", nil, &txtFakeDNS{})

	_, err := va.validateDNS01(ctx, identifier.NewIP(netip.MustParseAddr("127.0.0.1")), expectedKeyAuthorization)
	prob := detailedError(err)

	test.AssertEquals(t, prob.Type, probs.MalformedProblem)
}

func TestDNS01ValidationInvalid(t *testing.T) {
	var notDNS = identifier.ACMEIdentifier{
		Type:  identifier.IdentifierType("iris"),
		Value: "790DB180-A274-47A4-855F-31C428CB1072",
	}

	va, _ := setup(nil, "", nil, &txtFakeDNS{})

	_, err := va.validateDNS01(ctx, notDNS, expectedKeyAuthorization)
	prob := detailedError(err)

	test.AssertEquals(t, prob.Type, probs.MalformedProblem)
}

func TestDNS01ValidationServFail(t *testing.T) {
	va, _ := setup(nil, "", nil, &txtFakeDNS{})

	_, err := va.validateDNS01(ctx, identifier.NewDNS("servfail.com"), expectedKeyAuthorization)

	prob := detailedError(err)
	test.AssertEquals(t, prob.Type, probs.DNSProblem)
}

func TestDNS01ValidationNoServer(t *testing.T) {
	va, log := setup(nil, "", nil, &txtFakeDNS{})
	staticProvider, err := bdns.NewStaticProvider([]string{})
	test.AssertNotError(t, err, "Couldn't make new static provider")

	va.dnsClient = bdns.New(
		time.Second*5,
		staticProvider,
		metrics.NoopRegisterer,
		clock.New(),
		1,
		"",
		log,
		nil)

	_, err = va.validateDNS01(ctx, identifier.NewDNS("localhost"), expectedKeyAuthorization)
	prob := detailedError(err)
	test.AssertEquals(t, prob.Type, probs.DNSProblem)
}

func TestDNS01ValidationOK(t *testing.T) {
	va, _ := setup(nil, "", nil, &txtFakeDNS{})

	_, prob := va.validateDNS01(ctx, identifier.NewDNS("good-dns01.com"), expectedKeyAuthorization)

	test.Assert(t, prob == nil, "Should be valid.")
}

func TestDNS01ValidationNoAuthorityOK(t *testing.T) {
	va, _ := setup(nil, "", nil, &txtFakeDNS{})

	_, prob := va.validateDNS01(ctx, identifier.NewDNS("no-authority-dns01.com"), expectedKeyAuthorization)

	test.Assert(t, prob == nil, "Should be valid.")
}

func TestAvailableAddresses(t *testing.T) {
	v6a := netip.MustParseAddr("::1")
	v6b := netip.MustParseAddr("2001:db8::2:1") // 2001:DB8 is reserved for docs (RFC 3849)
	v4a := netip.MustParseAddr("127.0.0.1")
	v4b := netip.MustParseAddr("192.0.2.1") // 192.0.2.0/24 is reserved for docs (RFC 5737)

	testcases := []struct {
		input []netip.Addr
		v4    []netip.Addr
		v6    []netip.Addr
	}{
		// An empty validation record
		{
			[]netip.Addr{},
			[]netip.Addr{},
			[]netip.Addr{},
		},
		// A validation record with one IPv4 address
		{
			[]netip.Addr{v4a},
			[]netip.Addr{v4a},
			[]netip.Addr{},
		},
		// A dual homed record with an IPv4 and IPv6 address
		{
			[]netip.Addr{v4a, v6a},
			[]netip.Addr{v4a},
			[]netip.Addr{v6a},
		},
		// The same as above but with the v4/v6 order flipped
		{
			[]netip.Addr{v6a, v4a},
			[]netip.Addr{v4a},
			[]netip.Addr{v6a},
		},
		// A validation record with just IPv6 addresses
		{
			[]netip.Addr{v6a, v6b},
			[]netip.Addr{},
			[]netip.Addr{v6a, v6b},
		},
		// A validation record with interleaved IPv4/IPv6 records
		{
			[]netip.Addr{v6a, v4a, v6b, v4b},
			[]netip.Addr{v4a, v4b},
			[]netip.Addr{v6a, v6b},
		},
	}

	for _, tc := range testcases {
		// Split the input record into v4/v6 addresses
		v4result, v6result := availableAddresses(tc.input)

		// Test that we got the right number of v4 results
		test.Assert(t, len(tc.v4) == len(v4result),
			fmt.Sprintf("Wrong # of IPv4 results: expected %d, got %d", len(tc.v4), len(v4result)))

		// Check that all of the v4 results match expected values
		for i, v4addr := range tc.v4 {
			test.Assert(t, v4addr.String() == v4result[i].String(),
				fmt.Sprintf("Wrong v4 result index %d: expected %q got %q", i, v4addr.String(), v4result[i].String()))
		}

		// Test that we got the right number of v6 results
		test.Assert(t, len(tc.v6) == len(v6result),
			fmt.Sprintf("Wrong # of IPv6 results: expected %d, got %d", len(tc.v6), len(v6result)))

		// Check that all of the v6 results match expected values
		for i, v6addr := range tc.v6 {
			test.Assert(t, v6addr.String() == v6result[i].String(),
				fmt.Sprintf("Wrong v6 result index %d: expected %q got %q", i, v6addr.String(), v6result[i].String()))
		}
	}
}
