package policy

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/test"
)

var log = blog.UseMock()

var enabledChallenges = map[string]bool{
	core.ChallengeTypeHTTP01:   true,
	core.ChallengeTypeTLSSNI01: true,
	core.ChallengeTypeDNS01:    true,
}

func paImpl(t *testing.T) *AuthorityImpl {
	pa, err := New(enabledChallenges)
	if err != nil {
		t.Fatalf("Couldn't create policy implementation: %s", err)
	}
	return pa
}

func TestWillingToIssue(t *testing.T) {
	testCases := []struct {
		domain string
		err    error
	}{
		{``, errEmptyName},                    // Empty name
		{`zomb!.com`, errInvalidDNSCharacter}, // ASCII character out of range
		{`emailaddress@myseriously.present.com`, errInvalidDNSCharacter},
		{`user:pass@myseriously.present.com`, errInvalidDNSCharacter},
		{`zömbo.com`, errInvalidDNSCharacter},                              // non-ASCII character
		{`127.0.0.1`, errIPAddress},                                        // IPv4 address
		{`fe80::1:1`, errInvalidDNSCharacter},                              // IPv6 addresses
		{`[2001:db8:85a3:8d3:1319:8a2e:370:7348]`, errInvalidDNSCharacter}, // unexpected IPv6 variants
		{`[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443`, errInvalidDNSCharacter},
		{`2001:db8::/32`, errInvalidDNSCharacter},
		{`a.b.c.d.e.f.g.h.i.j.k`, errTooManyLabels}, // Too many labels (>10)

		{`www.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345.com`, errNameTooLong}, // Too long (254 characters)

		{`www.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.com`, errLabelTooLong}, // Label too long (>63 characters)

		{`www.-ombo.com`, errInvalidDNSCharacter}, // Label starts with '-'
		{`www.zomb-.com`, errInvalidDNSCharacter}, // Label ends with '-'
		{`xn--.net`, errInvalidDNSCharacter},      // Label ends with '-'
		{`0`, errTooFewLabels},
		{`1`, errTooFewLabels},
		{`*`, errInvalidDNSCharacter},
		{`**`, errInvalidDNSCharacter},
		{`*.*`, errInvalidDNSCharacter},
		{`zombo*com`, errInvalidDNSCharacter},
		{`*.com`, errInvalidDNSCharacter},
		{`*.zombo.com`, errInvalidDNSCharacter},
		{`..a`, errLabelTooShort},
		{`a..a`, errLabelTooShort},
		{`.a..a`, errLabelTooShort},
		{`..foo.com`, errLabelTooShort},
		{`.`, errNameEndsInDot},
		{`..`, errNameEndsInDot},
		{`a..`, errNameEndsInDot},
		{`.....`, errNameEndsInDot},
		{`.a.`, errNameEndsInDot},
		{`www.zombo.com.`, errNameEndsInDot},
		{`www.zombo_com.com`, errInvalidDNSCharacter},
		{`\uFEFF`, errInvalidDNSCharacter}, // Byte order mark
		{`\uFEFFwww.zombo.com`, errInvalidDNSCharacter},
		{`www.zom\u202Ebo.com`, errInvalidDNSCharacter}, // Right-to-Left Override
		{`\u202Ewww.zombo.com`, errInvalidDNSCharacter},
		{`www.zom\u200Fbo.com`, errInvalidDNSCharacter}, // Right-to-Left Mark
		{`\u200Fwww.zombo.com`, errInvalidDNSCharacter},
		// Underscores are technically disallowed in DNS. Some DNS
		// implementations accept them but we will be conservative.
		{`www.zom_bo.com`, errInvalidDNSCharacter},
		{`zombocom`, errTooFewLabels},
		{`localhost`, errTooFewLabels},
		{`mail`, errTooFewLabels},

		// disallow capitalized letters for #927
		{`CapitalizedLetters.com`, errInvalidDNSCharacter},

		{`example.acting`, errNonPublic},
		{`example.internal`, errNonPublic},
		// All-numeric final label not okay.
		{`www.zombo.163`, errNonPublic},
	}

	shouldBeTLDError := []string{
		`co.uk`,
		`foo.bn`,
	}

	shouldBeBlacklisted := []string{
		`highvalue.website1.org`,
		`website2.co.uk`,
		`www.website3.com`,
		`lots.of.labels.website4.com`,
	}
	blacklistContents := []string{
		`website2.com`,
		`website2.org`,
		`website2.co.uk`,
		`website3.com`,
		`website4.com`,
	}
	exactBlacklistContents := []string{
		`www.website1.org`,
		`highvalue.website1.org`,
		`dl.website1.org`,
	}

	shouldBeAccepted := []string{
		`lowvalue.website1.org`,
		`website4.sucks`,
		"www.unrelated.com",
		"unrelated.com",
		"www.8675309.com",
		"8675309.com",
		"web5ite2.com",
		"www.web-site2.com",
	}

	pa := paImpl(t)

	blacklistBytes, err := json.Marshal(blacklistJSON{
		Blacklist:      blacklistContents,
		ExactBlacklist: exactBlacklistContents,
	})
	test.AssertNotError(t, err, "Couldn't serialize blacklist")
	f, _ := ioutil.TempFile("", "test-blacklist.txt")
	defer os.Remove(f.Name())
	err = ioutil.WriteFile(f.Name(), blacklistBytes, 0640)
	test.AssertNotError(t, err, "Couldn't write blacklist")
	err = pa.SetHostnamePolicyFile(f.Name())
	test.AssertNotError(t, err, "Couldn't load rules")

	// Test for invalid identifier type
	identifier := core.AcmeIdentifier{Type: "ip", Value: "example.com"}
	err = pa.WillingToIssue(identifier)
	if err != errInvalidIdentifier {
		t.Error("Identifier was not correctly forbidden: ", identifier)
	}

	// Test syntax errors
	for _, tc := range testCases {
		identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: tc.domain}
		err := pa.WillingToIssue(identifier)
		if err != tc.err {
			t.Errorf("WillingToIssue(%q) = %q, expected %q", tc.domain, err, tc.err)
		}
	}

	// Invalid encoding
	err = pa.WillingToIssue(core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "www.xn--m.com"})
	test.AssertError(t, err, "WillingToIssue didn't fail on a malformed IDN")
	// Valid encoding
	err = pa.WillingToIssue(core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "www.xn--mnich-kva.com"})
	test.AssertNotError(t, err, "WillingToIssue failed on a properly formed IDN")
	// IDN TLD
	err = pa.WillingToIssue(core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "xn--example--3bhk5a.xn--p1ai"})
	test.AssertNotError(t, err, "WillingToIssue failed on a properly formed domain with IDN TLD")
	features.Reset()

	// Test domains that are equal to public suffixes
	for _, domain := range shouldBeTLDError {
		identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: domain}
		err := pa.WillingToIssue(identifier)
		if err != errICANNTLD {
			t.Error("Identifier was not correctly forbidden: ", identifier, err)
		}
	}

	// Test blacklisting
	for _, domain := range shouldBeBlacklisted {
		identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: domain}
		err := pa.WillingToIssue(identifier)
		if err != errBlacklisted {
			t.Error("Identifier was not correctly forbidden: ", identifier, err)
		}
	}

	// Test acceptance of good names
	for _, domain := range shouldBeAccepted {
		identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: domain}
		if err := pa.WillingToIssue(identifier); err != nil {
			t.Error("Identifier was incorrectly forbidden: ", identifier, err)
		}
	}
}

var accountKeyJSON = `{
  "kty":"RSA",
  "n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ",
  "e":"AQAB"
}`

func TestChallengesFor(t *testing.T) {
	pa := paImpl(t)

	challenges, combinations := pa.ChallengesFor(core.AcmeIdentifier{})

	test.Assert(t, len(challenges) == len(enabledChallenges), "Wrong number of challenges returned")
	test.Assert(t, len(combinations) == len(enabledChallenges), "Wrong number of combinations returned")

	seenChalls := make(map[string]bool)
	// Expected only if the pseudo-RNG is seeded with 99.
	expectedCombos := [][]int{{1}, {2}, {0}}
	for _, challenge := range challenges {
		test.Assert(t, !seenChalls[challenge.Type], "should not already have seen this type")
		seenChalls[challenge.Type] = true

		test.Assert(t, enabledChallenges[challenge.Type], "Unsupported challenge returned")
	}
	test.AssertEquals(t, len(seenChalls), len(enabledChallenges))
	test.AssertDeepEquals(t, expectedCombos, combinations)
}

func TestExtractDomainIANASuffix_Valid(t *testing.T) {
	testCases := []struct {
		domain, want string
	}{
		// TLD with only 1 rule.
		{"biz", "biz"},
		{"domain.biz", "biz"},
		{"b.domain.biz", "biz"},

		// The relevant {kobe,kyoto}.jp rules are:
		// jp
		// *.kobe.jp
		// !city.kobe.jp
		// kyoto.jp
		// ide.kyoto.jp
		{"jp", "jp"},
		{"kobe.jp", "jp"},
		{"c.kobe.jp", "c.kobe.jp"},
		{"b.c.kobe.jp", "c.kobe.jp"},
		{"a.b.c.kobe.jp", "c.kobe.jp"},
		{"city.kobe.jp", "kobe.jp"},
		{"www.city.kobe.jp", "kobe.jp"},
		{"kyoto.jp", "kyoto.jp"},
		{"test.kyoto.jp", "kyoto.jp"},
		{"ide.kyoto.jp", "ide.kyoto.jp"},
		{"b.ide.kyoto.jp", "ide.kyoto.jp"},
		{"a.b.ide.kyoto.jp", "ide.kyoto.jp"},

		// Domain with a private public suffix should return the ICANN public suffix.
		{"foo.compute-1.amazonaws.com", "com"},
		// Domain equal to a private public suffix should return the ICANN public
		// suffix.
		{"cloudapp.net", "net"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Case: %v", tc.domain), func(t *testing.T) {
			got, err := extractDomainIANASuffix(tc.domain)
			if err != nil {
				t.Errorf("%q: returned error", tc.domain)
			}
			if got != tc.want {
				t.Errorf("%q: got %q, want %q", tc.domain, got, tc.want)
			}
		})
	}
}

func TestExtractDomainIANASuffix_Invalid(t *testing.T) {
	testCases := []string{
		"",
		"example",
		"example.example",
	}

	for _, tc := range testCases {
		_, err := extractDomainIANASuffix(tc)
		if err == nil {
			t.Errorf("%q: expected err, got none", tc)
		}
	}
}
