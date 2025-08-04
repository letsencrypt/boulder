// dns_account_test.go
package va

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/bdns"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"
)

// Use a consistent test account URI, matching the example in the draft
const testAccountURI = "https://example.com/acme/acct/ExampleAccount"

func TestDNSAccount01Validation(t *testing.T) {
	testCases := []struct {
		name        string
		ident       identifier.ACMEIdentifier
		wantErrType berrors.ErrorType
		wantErrMsg  string
	}{
		{
			name:        "wrong TXT record",
			ident:       identifier.NewDNS("wrong-dns01.com"),
			wantErrType: berrors.Unauthorized,
			wantErrMsg:  "Incorrect TXT record",
		},
		{
			name:        "wrong TXT record with multiple values",
			ident:       identifier.NewDNS("wrong-many-dns01.com"),
			wantErrType: berrors.Unauthorized,
			wantErrMsg:  "Incorrect TXT record",
		},
		{
			name:        "wrong long TXT record",
			ident:       identifier.NewDNS("long-dns01.com"),
			wantErrType: berrors.Unauthorized,
			wantErrMsg:  "Incorrect TXT record",
		},
		{
			name:        "DNS failure on localhost",
			ident:       identifier.NewDNS("localhost"),
			wantErrType: berrors.Unauthorized,
			wantErrMsg:  "Incorrect TXT record",
		},
		{
			name:        "IP identifier not supported",
			ident:       identifier.NewIP(netip.MustParseAddr("127.0.0.1")),
			wantErrType: berrors.Malformed,
			wantErrMsg:  "Identifier type for DNS-ACCOUNT-01 challenge was not DNS",
		},
		{
			name: "invalid identifier type",
			ident: identifier.ACMEIdentifier{
				Type:  identifier.IdentifierType("iris"),
				Value: "790DB180-A274-47A4-855F-31C428CB1072",
			},
			wantErrType: berrors.Malformed,
			wantErrMsg:  "Identifier type for DNS-ACCOUNT-01 challenge was not DNS",
		},
		{
			name:        "DNS server failure",
			ident:       identifier.NewDNS("servfail.com"),
			wantErrType: berrors.DNS,
			wantErrMsg:  "SERVFAIL",
		},
		{
			name:  "valid DNS record",
			ident: identifier.NewDNS("good-dns01.com"),
		},
		{
			name:  "valid DNS record with no authority",
			ident: identifier.NewDNS("no-authority-dns01.com"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			va, _ := setup(nil, "", nil, nil)
			_, err := va.validateDNSAccount01(ctx, tc.ident, expectedKeyAuthorization, testAccountURI)

			if tc.wantErrMsg != "" {
				if err == nil {
					t.Errorf("validateDNSAccount01(%q) = success, but want error %q", tc.ident.Value, tc.wantErrMsg)
					return
				}
				if !errors.Is(err, tc.wantErrType) {
					t.Errorf("validateDNSAccount01(%q) = error type %T, but want error type %T", tc.ident.Value, err, tc.wantErrType)
				}
				prob := detailedError(err)
				if !strings.Contains(prob.String(), tc.wantErrMsg) {
					t.Errorf("validateDNSAccount01(%q) = %q, but want error containing %q", tc.ident.Value, prob.String(), tc.wantErrMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateDNSAccount01(%q) = %v, but want success", tc.ident.Value, err)
				}
			}
		})
	}
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

	_, err = va.validateDNSAccount01(ctx, identifier.NewDNS("localhost"), expectedKeyAuthorization, testAccountURI)
	prob := detailedError(err)
	test.AssertEquals(t, prob.Type, probs.DNSProblem)
}

func TestDNSAccount01ValidationEmptyAccountURI(t *testing.T) {
	va, _ := setup(nil, "", nil, nil)

	// The specific domain doesn't matter, as the function should
	// reject the empty accountURI before DNS lookup.
	ident := identifier.NewDNS("empty-uri-test.com")

	// Call the validation function with an empty accountURI
	_, err := va.validateDNSAccount01(ctx, ident, expectedKeyAuthorization, "")

	// Assert that an error was returned
	if err == nil {
		t.Errorf("validateDNSAccount01(%q) = success, but want error", ident.Value)
		return
	}

	// Assert the specific error type
	test.AssertErrorIs(t, err, berrors.InternalServer)

	// Assert the specific error message using strings.Contains
	wantErrMsg := "accountURI must be provided for dns-account-01"
	if !strings.Contains(err.Error(), wantErrMsg) {
		t.Errorf("validateDNSAccount01(%q) = %q, but want error containing %q", ident.Value, err.Error(), wantErrMsg)
	}
}
