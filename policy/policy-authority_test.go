// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package policy

import (
	"encoding/json"
	"testing"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

var log = mocks.UseMockLog()

var enabledChallenges = map[string]bool{
	core.ChallengeTypeHTTP01:   true,
	core.ChallengeTypeTLSSNI01: true,
	core.ChallengeTypeDNS01:    true,
}

func paImpl(t *testing.T) (*AuthorityImpl, func()) {
	dbMap, cleanUp := paDBMap(t)
	pa, err := New(dbMap, false, enabledChallenges)
	if err != nil {
		cleanUp()
		t.Fatalf("Couldn't create policy implementation: %s", err)
	}
	return pa, cleanUp
}

func paDBMap(t *testing.T) (*gorp.DbMap, func()) {
	dbMap, err := sa.NewDbMap(vars.DBConnPolicy)
	test.AssertNotError(t, err, "Could not construct dbMap")
	cleanUp := test.ResetPolicyTestDatabase(t)
	return dbMap, cleanUp
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

		{`www.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.com`, errNameTooLong}, // Too long (>255 characters)

		{`www.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.com`, errLabelTooLong}, // Label too long (>63 characters)

		{`www.-ombo.com`, errInvalidDNSCharacter}, // Label starts with '-'
		{`www.zomb-.com`, errInvalidDNSCharacter}, // Label ends with '-'
		{`xn--.net`, errInvalidDNSCharacter},      // Label ends with '-'
		{`www.xn--hmr.net`, errIDNNotSupported},   // Punycode (disallowed for now)
		{`0`, errTooFewLabels},
		{`1`, errTooFewLabels},
		{`*`, errInvalidDNSCharacter},
		{`**`, errInvalidDNSCharacter},
		{`*.*`, errInvalidDNSCharacter},
		{`zombo*com`, errInvalidDNSCharacter},
		{`*.com`, errInvalidDNSCharacter},
		{`*.zombo.com`, errInvalidDNSCharacter},
		{`.`, errLabelTooShort},
		{`..`, errLabelTooShort},
		{`a..`, errLabelTooShort},
		{`..a`, errLabelTooShort},
		{`.a.`, errLabelTooShort},
		{`.....`, errLabelTooShort},
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
		`addons.mozilla.org`,
		`ebay.co.uk`,
		`www.google.com`,
		`lots.of.labels.pornhub.com`,
	}

	shouldBeAccepted := []string{
		"www.zombo.com",
		"zombo.com",
		"www.8675309.com",
		"8675309.com",
		"zom2bo.com",
		"www.zom-bo.com",
	}

	pa, cleanup := paImpl(t)
	defer cleanup()

	rules := RuleSet{}
	for _, b := range shouldBeBlacklisted {
		rules.Blacklist = append(rules.Blacklist, BlacklistRule{Host: b})
	}
	err := pa.DB.LoadRules(rules)
	test.AssertNotError(t, err, "Couldn't load rules")

	// Test for invalid identifier type
	identifier := core.AcmeIdentifier{Type: "ip", Value: "example.com"}
	err = pa.WillingToIssue(identifier, 100)
	if err != errInvalidIdentifier {
		t.Error("Identifier was not correctly forbidden: ", identifier)
	}

	// Test syntax errors
	for _, tc := range testCases {
		identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: tc.domain}
		err := pa.WillingToIssue(identifier, 100)
		if err != tc.err {
			t.Errorf("WillingToIssue(%q) = %q, expected %q", tc.domain, err, tc.err)
		}
	}

	// Test domains that are equal to public suffixes
	for _, domain := range shouldBeTLDError {
		identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: domain}
		err := pa.WillingToIssue(identifier, 100)
		if err != errICANNTLD {
			t.Error("Identifier was not correctly forbidden: ", identifier, err)
		}
	}

	// Test blacklisting
	for _, domain := range shouldBeBlacklisted {
		identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: domain}
		err := pa.WillingToIssue(identifier, 100)
		if err != errBlacklisted {
			t.Error("Identifier was not correctly forbidden: ", identifier, err)
		}
	}

	// Test acceptance of good names
	for _, domain := range shouldBeAccepted {
		identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: domain}
		if err := pa.WillingToIssue(identifier, 100); err != nil {
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
	pa, cleanup := paImpl(t)
	defer cleanup()

	var accountKey *jose.JsonWebKey
	err := json.Unmarshal([]byte(accountKeyJSON), &accountKey)
	if err != nil {
		t.Errorf("Error unmarshaling JWK: %v", err)
	}

	challenges, combinations := pa.ChallengesFor(core.AcmeIdentifier{}, accountKey)

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

func TestWillingToIssueWithWhitelist(t *testing.T) {
	dbMap, cleanUp := paDBMap(t)
	defer cleanUp()
	pa, err := New(dbMap, true, nil)
	test.AssertNotError(t, err, "Couldn't create policy implementation")
	googID := core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: "www.google.com",
	}
	zomboID := core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: "www.zombo.com",
	}

	type listTestCase struct {
		regID int64
		id    core.AcmeIdentifier
		err   error
	}
	pa.DB.LoadRules(RuleSet{
		Whitelist: []WhitelistRule{
			{Host: "www.zombo.com"},
		},
	})

	// Note that www.google.com is not in the blacklist for this test. We no
	// longer have a hardcoded blacklist.
	testCases := []listTestCase{
		{100, googID, errNotWhitelisted},
		{whitelistedPartnerRegID, googID, nil},
		{100, zomboID, nil},
		{whitelistedPartnerRegID, zomboID, nil},
	}
	for _, tc := range testCases {
		err := pa.WillingToIssue(tc.id, tc.regID)
		if err != tc.err {
			t.Errorf("%#v, %d: want %#v, got %#v", tc.id.Value, tc.regID, tc.err, err)
		}
	}

	pa.DB.LoadRules(RuleSet{
		Blacklist: []BlacklistRule{
			{Host: "www.google.com"},
		},
		Whitelist: []WhitelistRule{
			{Host: "www.zombo.com"},
		},
	})

	exampleID := core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: "www.example.com",
	}

	testCases = []listTestCase{
		// This errNotWhitelisted is surprising and accidental from the ordering
		// of the whitelist and blacklist check. The whitelist will be gone soon
		// enough.
		{100, googID, errNotWhitelisted},
		{whitelistedPartnerRegID, googID, errBlacklisted},
		{100, zomboID, nil},
		{whitelistedPartnerRegID, zomboID, nil},
		{100, exampleID, errNotWhitelisted},
		{whitelistedPartnerRegID, exampleID, nil},
	}
	for _, tc := range testCases {
		err := pa.WillingToIssue(tc.id, tc.regID)
		if err != tc.err {
			t.Errorf("%#v, %d: want %#v, got %#v", tc.id.Value, tc.regID, tc.err, err)
		}
	}

	pa.DB.LoadRules(RuleSet{
		Blacklist: []BlacklistRule{
			{Host: "www.google.com"},
		},
		Whitelist: []WhitelistRule{
			{Host: "www.zombo.com"},
			{Host: "www.google.com"},
		},
	})
	testCases = []listTestCase{
		{100, googID, errBlacklisted},
		{whitelistedPartnerRegID, googID, errBlacklisted},
		{100, zomboID, nil},
		{whitelistedPartnerRegID, zomboID, nil},
		{100, exampleID, errNotWhitelisted},
		{whitelistedPartnerRegID, exampleID, nil},
	}
	for _, tc := range testCases {
		err := pa.WillingToIssue(tc.id, tc.regID)
		if err != tc.err {
			t.Errorf("%#v, %d: want %#v, got %#v", tc.id.Value, tc.regID, tc.err, err)
		}
	}
}
