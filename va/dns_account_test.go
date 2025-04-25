// dns_account_test.go
package va

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"
)

// Use a consistent test account URL, matching the example in the draft
const testAccountURL = "https://example.com/acme/acct/ExampleAccount"

// Expected label prefix derived from testAccountURL (as per draft example)
const expectedLabelPrefix = "_ujmmovf2vn55tgye._acme-challenge"

func TestDNSAccount01ValidationWrong(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)
	_, err := va.validateDNSAccount01(context.Background(), identifier.NewDNS("wrong-dns01.com"), expectedKeyAuthorization, testAccountURL)
	if err == nil {
		t.Fatalf("Successful DNS validation with wrong TXT record")
	}
	prob := detailedError(err)
	expectedErr := "unauthorized :: Incorrect TXT record \"a\" found at " + expectedLabelPrefix + ".wrong-dns01.com" +
		" (account: " + testAccountURL + ")"
	test.AssertEquals(t, prob.String(), expectedErr)
}

func TestDNSAccount01ValidationWrongMany(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)

	_, err := va.validateDNSAccount01(context.Background(), identifier.NewDNS("wrong-many-dns01.com"), expectedKeyAuthorization, testAccountURL)
	if err == nil {
		t.Fatalf("Successful DNS validation with wrong TXT record")
	}
	prob := detailedError(err)
	expectedErr := "unauthorized :: Incorrect TXT record \"a\" (and 4 more) found at " + expectedLabelPrefix + ".wrong-many-dns01.com" +
		" (account: " + testAccountURL + ")"
	test.AssertEquals(t, prob.String(), expectedErr)
}

func TestDNSAccount01ValidationWrongLong(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)

	_, err := va.validateDNSAccount01(context.Background(), identifier.NewDNS("long-dns01.com"), expectedKeyAuthorization, testAccountURL)
	if err == nil {
		t.Fatalf("Successful DNS validation with wrong TXT record")
	}
	prob := detailedError(err)
	expectedErr := "unauthorized :: Incorrect TXT record \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...\" found at " + expectedLabelPrefix + ".long-dns01.com" +
		" (account: " + testAccountURL + ")"
	test.AssertEquals(t, prob.String(), expectedErr)
}

func TestDNSAccount01ValidationFailure(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)

	_, err := va.validateDNSAccount01(ctx, identifier.NewDNS("localhost"), expectedKeyAuthorization, testAccountURL)
	prob := detailedError(err)

	test.AssertEquals(t, prob.Type, probs.UnauthorizedProblem)

	expectedErr := "unauthorized :: Incorrect TXT record \"hostname\" found at " + expectedLabelPrefix + ".localhost" +
		" (account: " + testAccountURL + ")"
	test.AssertEquals(t, prob.String(), expectedErr)
}

func TestDNSAccount01ValidationIP(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)

	_, err := va.validateDNSAccount01(ctx, identifier.NewIP(netip.MustParseAddr("127.0.0.1")), expectedKeyAuthorization, testAccountURL)
	prob := detailedError(err)

	test.AssertEquals(t, prob.Type, probs.MalformedProblem)
}

func TestDNSAccount01ValidationInvalid(t *testing.T) {
	var notDNS = identifier.ACMEIdentifier{
		Type:  identifier.IdentifierType("iris"),
		Value: "790DB180-A274-47A4-855F-31C428CB1072",
	}

	va, _ := setup(nil, "", nil, nil)

	_, err := va.validateDNSAccount01(ctx, notDNS, expectedKeyAuthorization, testAccountURL)
	prob := detailedError(err)

	test.AssertEquals(t, prob.Type, probs.MalformedProblem)
}

func TestDNSAccount01ValidationServFail(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)

	_, err := va.validateDNSAccount01(ctx, identifier.NewDNS("servfail.com"), expectedKeyAuthorization, testAccountURL)

	prob := detailedError(err)
	test.AssertEquals(t, prob.Type, probs.DNSProblem)
}

func TestDNSAccount01ValidationNoServer(t *testing.T) {
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

	_, err = va.validateDNSAccount01(ctx, identifier.NewDNS("localhost"), expectedKeyAuthorization, testAccountURL)
	prob := detailedError(err)
	test.AssertEquals(t, prob.Type, probs.DNSProblem)
}

func TestDNSAccount01ValidationOK(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)

	_, prob := va.validateDNSAccount01(ctx, identifier.NewDNS("good-dns01.com"), expectedKeyAuthorization, testAccountURL)

	test.Assert(t, prob == nil, "Should be valid.")
}

func TestDNSAccount01ValidationNoAuthorityOK(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)

	_, prob := va.validateDNSAccount01(ctx, identifier.NewDNS("no-authority-dns01.com"), expectedKeyAuthorization, testAccountURL)

	test.Assert(t, prob == nil, "Should be valid.")
}

func TestDNSAccount01ValidationEmptyAccountURI(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)

	// The specific domain doesn't matter, as the function should
	// reject the empty accountURI before DNS lookup.
	ident := identifier.NewDNS("empty-uri-test.com")

	// Call the validation function with an empty accountURI
	_, err := va.validateDNSAccount01(ctx, ident, expectedKeyAuthorization, "")

	// Assert that an error was returned
	test.Assert(t, err != nil, "validateDNSAccount01 succeeded unexpectedly with an empty account URI")

	// Assert the specific error type
	prob := detailedError(err)
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)

	// Assert the specific error message
	expectedErrMsg := "connection :: Error getting validation data"
	test.AssertEquals(t, prob.String(), expectedErrMsg)
}
