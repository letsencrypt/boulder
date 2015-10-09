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
)

var log = mocks.UseMockLog()
var dbConnStr = "mysql+tcp://boulder@localhost:3306/boulder_policy_test"

func paImpl(t *testing.T) (*PolicyAuthorityImpl, func()) {
	dbMap, cleanUp := paDBMap(t)
	pa, err := NewPolicyAuthorityImpl(dbMap, false)
	if err != nil {
		cleanUp()
		t.Fatalf("Couldn't create policy implementation: %s", err)
	}
	return pa, cleanUp
}

func paDBMap(t *testing.T) (*gorp.DbMap, func()) {
	dbMap, err := sa.NewDbMap(dbConnStr)
	test.AssertNotError(t, err, "Could not construct dbMap")
	cleanUp := test.ResetTestDatabase(t, dbMap.Db)
	return dbMap, cleanUp
}

func TestWillingToIssue(t *testing.T) {
	shouldBeSyntaxError := []string{
		``,          // Empty name
		`zomb!.com`, // ASCII character out of range
		`emailaddress@myseriously.present.com`,
		`user:pass@myseriously.present.com`,
		`zömbo.com`,                              // non-ASCII character
		`127.0.0.1`,                              // IPv4 address
		`fe80::1:1`,                              // IPv6 addresses
		`[2001:db8:85a3:8d3:1319:8a2e:370:7348]`, // unexpected IPv6 variants
		`[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443`,
		`2001:db8::/32`,
		`a.b.c.d.e.f.g.h.i.j.k`, // Too many labels (>10)

		`www.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.com`, // Too long (>255 characters)

		`www.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.com`, // Label too long (>63 characters)

		`www.-ombo.com`,   // Label starts with '-'
		`www.xn--hmr.net`, // Punycode (disallowed for now)
		`xn--.net`,        // No punycode for now.
		`0`,
		`1`,
		`*`,
		`**`,
		`*.*`,
		`zombo*com`,
		`*.com`,
		`*.zombo.com`,
		`.`,
		`..`,
		`a..`,
		`..a`,
		`.a.`,
		`.....`,
		`www.zombo_com.com`,
		`\uFEFF`, // Byte order mark
		`\uFEFFwww.zombo.com`,
		`www.zom\u202Ebo.com`, // Right-to-Left Override
		`\u202Ewww.zombo.com`,
		`www.zom\u200Fbo.com`, // Right-to-Left Mark
		`\u200Fwww.zombo.com`,
		// Underscores are technically disallowed in DNS. Some DNS
		// implementations accept them but we will be conservative.
		`www.zom_bo.com`,
		`zombocom`,
		`localhost`,
		`mail`,

		// disallow capitalized letters for #927
		`CapitalizedLetters.com`,
	}

	shouldBeNonPublic := []string{
		`co.uk`,
		`example.acting`,
		`example.internal`,
		// All-numeric final label not okay.
		`www.zombo.163`,
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
		"zombo-.com",
		"www.zom-bo.com",
		"www.zombo-.com",
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
	_, ok := err.(InvalidIdentifierError)
	if !ok {
		t.Error("Identifier was not correctly forbidden: ", identifier)
	}

	// Test syntax errors
	for _, domain := range shouldBeSyntaxError {
		identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: domain}
		err := pa.WillingToIssue(identifier, 100)
		_, ok := err.(SyntaxError)
		if !ok {
			t.Error("Identifier was not correctly forbidden: ", identifier, err)
		}
	}

	// Test public suffix matching
	for _, domain := range shouldBeNonPublic {
		identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: domain}
		err := pa.WillingToIssue(identifier, 100)
		_, ok := err.(NonPublicError)
		if !ok {
			t.Error("Identifier was not correctly forbidden: ", identifier, err)
		}
	}

	// Test blacklisting
	for _, domain := range shouldBeBlacklisted {
		identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: domain}
		err := pa.WillingToIssue(identifier, 100)
		if err != ErrBlacklisted {
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

	challenges, combinations, err := pa.ChallengesFor(core.AcmeIdentifier{}, accountKey)
	if err != nil {
		t.Errorf("Error generating challenges: %v", err)
	}

	// TODO(https://github.com/letsencrypt/boulder/issues/894): Update these tests
	if len(challenges) != 4 ||
		challenges[0].Type != core.ChallengeTypeSimpleHTTP ||
		challenges[1].Type != core.ChallengeTypeDVSNI ||
		challenges[2].Type != core.ChallengeTypeHTTP01 ||
		challenges[3].Type != core.ChallengeTypeTLSSNI01 {
		t.Error("Incorrect challenges returned")
	}
	if len(combinations) != 4 ||
		combinations[0][0] != 0 || combinations[1][0] != 1 ||
		combinations[2][0] != 2 || combinations[3][0] != 3 {
		t.Error("Incorrect combinations returned")
	}
}

func TestWillingToIssueWithWhitelist(t *testing.T) {
	dbMap, cleanUp := paDBMap(t)
	defer cleanUp()
	pa, err := NewPolicyAuthorityImpl(dbMap, true)
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
		{100, googID, ErrNotWhitelisted},
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
		// This ErrNotWhitelisted is surprising and accidental from the ordering
		// of the whitelist and blacklist check. The whitelist will be gone soon
		// enough.
		{100, googID, ErrNotWhitelisted},
		{whitelistedPartnerRegID, googID, ErrBlacklisted},
		{100, zomboID, nil},
		{whitelistedPartnerRegID, zomboID, nil},
		{100, exampleID, ErrNotWhitelisted},
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
		{100, googID, ErrBlacklisted},
		{whitelistedPartnerRegID, googID, ErrBlacklisted},
		{100, zomboID, nil},
		{whitelistedPartnerRegID, zomboID, nil},
		{100, exampleID, ErrNotWhitelisted},
		{whitelistedPartnerRegID, exampleID, nil},
	}
	for _, tc := range testCases {
		err := pa.WillingToIssue(tc.id, tc.regID)
		if err != tc.err {
			t.Errorf("%#v, %d: want %#v, got %#v", tc.id.Value, tc.regID, tc.err, err)
		}
	}
}
