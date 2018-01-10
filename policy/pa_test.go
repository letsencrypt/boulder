package policy

import (
	"encoding/json"
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

		{`www.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345.com`, errNameTooLong}, // Too long (240 characters)

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
		{`xn--109-3veba6djs1bfxlfmx6c9g.xn--f1awi.xn--p1ai`, errMalformedIDN}, // Not in Unicode NFKC
		{`bq--abwhky3f6fxq.jakacomo.com`, errInvalidRLDH},
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

func TestWillingToIssueWildcard(t *testing.T) {
	bannedDomains := []string{
		"zombo.gov.us",
	}
	exactBannedDomains := []string{
		"highvalue.letsdecrypt.org",
	}
	pa := paImpl(t)

	bannedBytes, err := json.Marshal(blacklistJSON{
		Blacklist:      bannedDomains,
		ExactBlacklist: exactBannedDomains,
	})
	test.AssertNotError(t, err, "Couldn't serialize banned list")
	f, _ := ioutil.TempFile("", "test-wildcard-banlist.txt")
	defer os.Remove(f.Name())
	err = ioutil.WriteFile(f.Name(), bannedBytes, 0640)
	test.AssertNotError(t, err, "Couldn't write serialized banned list to file")
	err = pa.SetHostnamePolicyFile(f.Name())
	test.AssertNotError(t, err, "Couldn't load policy contents from file")

	makeDNSIdent := func(domain string) core.AcmeIdentifier {
		return core.AcmeIdentifier{
			Type:  core.IdentifierDNS,
			Value: domain,
		}
	}

	testCases := []struct {
		Name        string
		Ident       core.AcmeIdentifier
		ExpectedErr error
	}{
		{
			Name:        "Non-DNS identifier",
			Ident:       core.AcmeIdentifier{Type: "nickname", Value: "cpu"},
			ExpectedErr: errInvalidIdentifier,
		},
		{
			Name:        "Too many wildcards",
			Ident:       makeDNSIdent("ok.*.whatever.*.example.com"),
			ExpectedErr: errTooManyWildcards,
		},
		{
			Name:        "Misplaced wildcard",
			Ident:       makeDNSIdent("ok.*.whatever.example.com"),
			ExpectedErr: errMalformedWildcard,
		},
		{
			Name:        "Missing ICANN TLD",
			Ident:       makeDNSIdent("*.ok.madeup"),
			ExpectedErr: errNonPublic,
		},
		{
			Name:        "Wildcard for ICANN TLD",
			Ident:       makeDNSIdent("*.com"),
			ExpectedErr: errICANNTLDWildcard,
		},
		{
			Name:        "Forbidden base domain",
			Ident:       makeDNSIdent("*.zombo.gov.us"),
			ExpectedErr: errBlacklisted,
		},
		// We should not allow getting a wildcard for that would cover an exact
		// blocklist domain
		{
			Name:        "Wildcard for ExactBlacklist base domain",
			Ident:       makeDNSIdent("*.letsdecrypt.org"),
			ExpectedErr: errBlacklisted,
		},
		// We should allow a wildcard for a domain that doesn't match the exact
		// blacklist domain
		{
			Name:        "Wildcard for non-matching subdomain of ExactBlacklist domain",
			Ident:       makeDNSIdent("*.lowvalue.letsdecrypt.org"),
			ExpectedErr: nil,
		},
		// We should allow getting a wildcard for an exact blacklist domain since it
		// only covers subdomains, not the exact name.
		{
			Name:        "Wildcard for ExactBlacklist domain",
			Ident:       makeDNSIdent("*.highvalue.letsdecrypt.org"),
			ExpectedErr: nil,
		},
		{
			Name:        "Valid wildcard domain",
			Ident:       makeDNSIdent("*.everything.is.possible.at.zombo.com"),
			ExpectedErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result := pa.WillingToIssueWildcard(tc.Ident)
			test.AssertEquals(t, result, tc.ExpectedErr)
		})
	}
}

var accountKeyJSON = `{
  "kty":"RSA",
  "n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ",
  "e":"AQAB"
}`

func TestChallengesFor(t *testing.T) {
	pa := paImpl(t)

	challenges, combinations, err := pa.ChallengesFor(core.AcmeIdentifier{})
	test.AssertNotError(t, err, "ChallengesFor failed")

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

func TestChallengesForWildcard(t *testing.T) {
	// wildcardIdent is an identifier for a wildcard domain name
	wildcardIdent := core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: "*.zombo.com",
	}

	mustConstructPA := func(t *testing.T, enabledChallenges map[string]bool) *AuthorityImpl {
		pa, err := New(enabledChallenges)
		test.AssertNotError(t, err, "Couldn't create policy implementation")
		return pa
	}

	// First try to get a challenge for the wildcard ident without the
	// DNS-01 challenge type enabled. This should produce an error
	var enabledChallenges = map[string]bool{
		core.ChallengeTypeHTTP01:   true,
		core.ChallengeTypeTLSSNI01: true,
		core.ChallengeTypeDNS01:    false,
	}
	pa := mustConstructPA(t, enabledChallenges)
	_, _, err := pa.ChallengesFor(wildcardIdent)
	test.AssertError(t, err, "ChallengesFor did not error for a wildcard ident "+
		"when DNS-01 was disabled")
	test.AssertEquals(t, err.Error(), "Challenges requested for wildcard "+
		"identifier but DNS-01 challenge type is not enabled")

	// Try again with DNS-01 enabled. It should not error and
	// should return only one DNS-01 type challenge
	enabledChallenges[core.ChallengeTypeDNS01] = true
	pa = mustConstructPA(t, enabledChallenges)
	challenges, combinations, err := pa.ChallengesFor(wildcardIdent)
	test.AssertNotError(t, err, "ChallengesFor errored for a wildcard ident "+
		"unexpectedly")
	test.AssertEquals(t, len(combinations), 1)
	test.AssertEquals(t, len(challenges), 1)
	test.AssertEquals(t, challenges[0].Type, core.ChallengeTypeDNS01)
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
		got, err := extractDomainIANASuffix(tc.domain)
		if err != nil {
			t.Errorf("%q: returned error", tc.domain)
			continue
		}
		if got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.domain, got, tc.want)
		}
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

// TestMalformedExactBlacklist tests that loading a JSON policy file with an
// invalid exact blacklist entry will fail as expected.
func TestMalformedExactBlacklist(t *testing.T) {
	pa := paImpl(t)

	exactBannedDomains := []string{
		// Only one label - not valid
		"com",
	}
	bannedDomains := []string{
		"placeholder.domain.not.important.for.this.test.com",
	}

	// Create JSON for the exactBannedDomains
	bannedBytes, err := json.Marshal(blacklistJSON{
		Blacklist:      bannedDomains,
		ExactBlacklist: exactBannedDomains,
	})
	test.AssertNotError(t, err, "Couldn't serialize banned list")

	// Create a temp file for the JSON contents
	f, _ := ioutil.TempFile("", "test-invalid-exactblacklist.json")
	defer os.Remove(f.Name())
	// Write the JSON to the temp file
	err = ioutil.WriteFile(f.Name(), bannedBytes, 0640)
	test.AssertNotError(t, err, "Couldn't write serialized banned list to file")

	// Try to use the JSON tempfile as the hostname policy. It should produce an
	// error since the exact blacklist contents are malformed.
	err = pa.SetHostnamePolicyFile(f.Name())
	test.AssertError(t, err, "Loaded invalid exact blacklist content without error")
	test.AssertEquals(t, err.Error(), "Malformed exact blacklist entry, only one label: \"com\"")
}

func TestChallengeStillAllowed(t *testing.T) {
	pa := paImpl(t)
	pa.enabledChallenges[core.ChallengeTypeHTTP01] = false
	test.Assert(t, !pa.ChallengeStillAllowed(&core.Authorization{}), "pa.ChallengeStillAllowed didn't fail with empty authorization")
	test.Assert(t, !pa.ChallengeStillAllowed(&core.Authorization{Challenges: []core.Challenge{{Status: core.StatusPending}}}), "pa.ChallengeStillAllowed didn't fail with no valid challenges")
	test.Assert(t, !pa.ChallengeStillAllowed(&core.Authorization{Challenges: []core.Challenge{{Status: core.StatusValid, Type: core.ChallengeTypeHTTP01}}}), "pa.ChallengeStillAllowed didn't fail with disabled challenge")

	test.Assert(t, pa.ChallengeStillAllowed(&core.Authorization{Challenges: []core.Challenge{{Status: core.StatusValid, Type: core.ChallengeTypeTLSSNI01}}}), "pa.ChallengeStillAllowed failed with enabled challenge")
}
