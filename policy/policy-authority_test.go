// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package policy

import (
	"testing"

	"github.com/letsencrypt/boulder/core"
)

func TestWillingToIssue(t *testing.T) {
	shouldBeSyntaxError := []string{
		``,                      // Empty name
		`zomb!.com`,             // ASCII character out of range
		`zömbo.com`,             // non-ASCII character
		`127.0.0.1`,             // IP address
		`a.b.c.d.e.f.g.h.i.j.k`, // Too many labels (>10)

		`www.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.com`, // Too long (>255 characters)

		`www.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.com`, // Label too long (>63 characters)

		`www.-ombo.com`,   // Label starts with '-'
		`www.xn--hmr.net`, // Punycode (disallowed for now)
	}

	shouldBeNonPublic := []string{
		`co.uk`,
		`example.acting`,
		`example.internal`,
	}

	shouldBeBlacklisted := []string{
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

	pa := NewPolicyAuthorityImpl()

	// Test for invalid identifier type
	identifier := core.AcmeIdentifier{Type: "ip", Value: "example.com"}
	err := pa.WillingToIssue(identifier)
	if err != InvalidIdentifierError {
		t.Error("Identifier was not correctly forbidden: ", identifier)
	}

	// Test syntax errors
	for _, domain := range shouldBeSyntaxError {
		identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: domain}
		if err := pa.WillingToIssue(identifier); err != SyntaxError {
			t.Error("Identifier was not correctly forbidden: ", identifier, err)
		}
	}

	// Test public suffix matching
	for _, domain := range shouldBeNonPublic {
		identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: domain}
		if err := pa.WillingToIssue(identifier); err != NonPublicError {
			t.Error("Identifier was not correctly forbidden: ", identifier, err)
		}
	}

	// Test blacklisting
	for _, domain := range shouldBeBlacklisted {
		identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: domain}
		if err := pa.WillingToIssue(identifier); err != BlacklistedError {
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

func TestChallengesFor(t *testing.T) {
	pa := NewPolicyAuthorityImpl()

	challenges, combinations := pa.ChallengesFor(core.AcmeIdentifier{})

	if len(challenges) != 2 || challenges[0].Type != core.ChallengeTypeSimpleHTTPS ||
		challenges[1].Type != core.ChallengeTypeDVSNI {
		t.Error("Incorrect challenges returned")
	}
	if len(combinations) != 2 || combinations[0][0] != 0 || combinations[1][0] != 1 {
		t.Error("Incorrect combinations returned")
	}
}
