package va

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/identifier"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"
)

func TestDNSValidationWrong(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)
	_, err := va.validateDNS01(context.Background(), identifier.NewDNS("wrong-dns01.com"), expectedKeyAuthorization)
	if err == nil {
		t.Fatalf("Successful DNS validation with wrong TXT record")
	}
	prob := detailedError(err)
	test.AssertEquals(t, prob.String(), "unauthorized :: Incorrect TXT record \"a\" found at _acme-challenge.wrong-dns01.com")
}

func TestDNSValidationWrongMany(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)

	_, err := va.validateDNS01(context.Background(), identifier.NewDNS("wrong-many-dns01.com"), expectedKeyAuthorization)
	if err == nil {
		t.Fatalf("Successful DNS validation with wrong TXT record")
	}
	prob := detailedError(err)
	test.AssertEquals(t, prob.String(), "unauthorized :: Incorrect TXT record \"a\" (and 4 more) found at _acme-challenge.wrong-many-dns01.com")
}

func TestDNSValidationWrongLong(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)

	_, err := va.validateDNS01(context.Background(), identifier.NewDNS("long-dns01.com"), expectedKeyAuthorization)
	if err == nil {
		t.Fatalf("Successful DNS validation with wrong TXT record")
	}
	prob := detailedError(err)
	test.AssertEquals(t, prob.String(), "unauthorized :: Incorrect TXT record \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...\" found at _acme-challenge.long-dns01.com")
}

func TestDNSValidationFailure(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)

	_, err := va.validateDNS01(ctx, identifier.NewDNS("localhost"), expectedKeyAuthorization)
	prob := detailedError(err)

	test.AssertEquals(t, prob.Type, probs.UnauthorizedProblem)
}

func TestDNSValidationIP(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)

	_, err := va.validateDNS01(ctx, identifier.NewIP(netip.MustParseAddr("127.0.0.1")), expectedKeyAuthorization)
	prob := detailedError(err)

	test.AssertEquals(t, prob.Type, probs.MalformedProblem)
}

func TestDNSValidationInvalid(t *testing.T) {
	var notDNS = identifier.ACMEIdentifier{
		Type:  identifier.IdentifierType("iris"),
		Value: "790DB180-A274-47A4-855F-31C428CB1072",
	}

	va, _ := setup(nil, "", nil, nil)

	_, err := va.validateDNS01(ctx, notDNS, expectedKeyAuthorization)
	prob := detailedError(err)

	test.AssertEquals(t, prob.Type, probs.MalformedProblem)
}

func TestDNSValidationServFail(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)

	_, err := va.validateDNS01(ctx, identifier.NewDNS("servfail.com"), expectedKeyAuthorization)

	prob := detailedError(err)
	test.AssertEquals(t, prob.Type, probs.DNSProblem)
}

func TestDNSValidationNoServer(t *testing.T) {
	va, log := setup(nil, "", nil, nil)
	staticProvider, err := bdns.NewStaticProvider([]string{})
	test.AssertNotError(t, err, "Couldn't make new static provider")

	va.dnsClient = bdns.NewTest(
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

func TestDNSValidationOK(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)

	_, prob := va.validateDNS01(ctx, identifier.NewDNS("good-dns01.com"), expectedKeyAuthorization)

	test.Assert(t, prob == nil, "Should be valid.")
}

func TestDNSValidationNoAuthorityOK(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)

	_, prob := va.validateDNS01(ctx, identifier.NewDNS("no-authority-dns01.com"), expectedKeyAuthorization)

	test.Assert(t, prob == nil, "Should be valid.")
}

// Expected labels for the test cases are calculated using
// https://github.com/aaomidi/draft-ietf-acme-scoped-dns-challenges/blob/d7d9770d473e47da445ea9dd96c7f79672341c8c/examples/label.go
func TestCalculateDNSAccount01Label(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)

	testCases := []struct {
		name        string
		accountURL  string
		expected    string
		description string
	}{
		{
			name:        "RFC Example",
			accountURL:  "https://example.com/acme/acct/ExampleAccount",
			expected:    "ujmmovf2vn55tgye",
			description: "This matches the example in draft-ietf-acme-dns-account-label-00",
		},
		{
			name:        "Local Development",
			accountURL:  "http://localhost:4000/acme/acct/1",
			expected:    "vkbgbqfhr6yv2asd",
			description: "Common local development URL format",
		},
		{
			name:        "Production URL",
			accountURL:  "https://acme-v02.api.letsencrypt.org/acme/acct/12345",
			expected:    "lvrajhh53e27yh7f",
			description: "Let's Encrypt production URL format",
		},
		{
			name:        "Staging URL",
			accountURL:  "https://acme-staging-v02.api.letsencrypt.org/acme/acct/67890",
			expected:    "2slyxozq54jc5ljm",
			description: "Let's Encrypt staging URL format",
		},
		{
			name:        "Long URL",
			accountURL:  "https://extremely-long-domain-name-for-testing-purposes-that-exceeds-normal-length.example.com/acme/account/with/long/path/12345",
			expected:    "7e32ve5ka75ittru",
			description: "Extremely long URL to test hash truncation",
		},
		{
			name:        "URL with Special Characters",
			accountURL:  "https://example.com/acme/acct/User+Name@example.com",
			expected:    "qlp75edvqankci3c",
			description: "URL with special characters that need encoding",
		},
		{
			name:        "Empty URL",
			accountURL:  "",
			expected:    "4oymiquy7qobjgx3",
			description: "Edge case: empty URL",
		},
		{
			name:        "URL with Unicode",
			accountURL:  "https://例子.测试/acme/acct/12345",
			expected:    "idm5i43k6wemcnem",
			description: "URL with Unicode characters",
		},
		{
			name:        "URL with Query Parameters",
			accountURL:  "https://example.com/acme/acct/12345?param=value&other=thing",
			expected:    "a4tgldxnu6oq5fgs",
			description: "URL with query parameters",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := va.calculateDNSAccount01Label(tc.accountURL)
			if result != tc.expected {
				t.Errorf("Expected %q, got %q for account URL %q (%s)",
					tc.expected, result, tc.accountURL, tc.description)
			}
		})
	}
}

func TestValidateDNSAccount01(t *testing.T) {
	mockDNS := &bdns.MockClient{Log: blog.NewMock()}
	va, _ := setup(nil, "", nil, mockDNS)

	features.Set(features.Config{DNSAccount01Enabled: true})
	defer features.Reset()

	accountURL := "https://example.com/acme/acct/ExampleAccount"
	wrongAccountURL := "https://example.com/acme/acct/WrongAccount"
	domain := "good-dns01.com"
	wrongDomain := "wrong-dns01.com"
	ipIdentifier := identifier.NewIP(netip.MustParseAddr("127.0.0.1"))

	t.Run("Wrong Identifier Type", func(t *testing.T) {
		_, err := va.validateDNSAccount01(ctx, ipIdentifier, expectedKeyAuthorization, accountURL)
		test.AssertError(t, err, "Should be invalid with IP identifier")
		test.AssertEquals(t, err.Error(), "Identifier type for DNS challenge was not DNS")
	})

	t.Run("Wrong DNS Record", func(t *testing.T) {
		_, err := va.validateDNSAccount01(ctx, identifier.NewDNS(wrongDomain), expectedKeyAuthorization, accountURL)
		test.AssertError(t, err, "Should be invalid with wrong DNS record")
		test.AssertContains(t, err.Error(), "Incorrect TXT record")
	})

	t.Run("Wrong Account URL", func(t *testing.T) {
		_, err := va.validateDNSAccount01(ctx, identifier.NewDNS(domain), expectedKeyAuthorization, wrongAccountURL)
		test.AssertError(t, err, "Should be invalid with wrong account URL")
		test.AssertContains(t, err.Error(), "Incorrect TXT record")
	})

	t.Run("Valid Account URL and DNS Record", func(t *testing.T) {
		_, err := va.validateDNSAccount01(ctx, identifier.NewDNS(domain), expectedKeyAuthorization, accountURL)
		test.AssertNotError(t, err, "Should be valid with correct account URL and DNS record")
	})
}

func TestAvailableAddresses(t *testing.T) {
	v6a := net.ParseIP("::1")
	v6b := net.ParseIP("2001:db8::2:1") // 2001:DB8 is reserved for docs (RFC 3849)
	v4a := net.ParseIP("127.0.0.1")
	v4b := net.ParseIP("192.0.2.1") // 192.0.2.0/24 is reserved for docs (RFC 5737)

	testcases := []struct {
		input []net.IP
		v4    []net.IP
		v6    []net.IP
	}{
		// An empty validation record
		{
			[]net.IP{},
			[]net.IP{},
			[]net.IP{},
		},
		// A validation record with one IPv4 address
		{
			[]net.IP{v4a},
			[]net.IP{v4a},
			[]net.IP{},
		},
		// A dual homed record with an IPv4 and IPv6 address
		{
			[]net.IP{v4a, v6a},
			[]net.IP{v4a},
			[]net.IP{v6a},
		},
		// The same as above but with the v4/v6 order flipped
		{
			[]net.IP{v6a, v4a},
			[]net.IP{v4a},
			[]net.IP{v6a},
		},
		// A validation record with just IPv6 addresses
		{
			[]net.IP{v6a, v6b},
			[]net.IP{},
			[]net.IP{v6a, v6b},
		},
		// A validation record with interleaved IPv4/IPv6 records
		{
			[]net.IP{v6a, v4a, v6b, v4b},
			[]net.IP{v4a, v4b},
			[]net.IP{v6a, v6b},
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
