// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package policy

import (
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/test"
)

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

	pa, err := NewPolicyAuthorityImpl(Config{
		Driver: "sqlite3",
		Name:   ":memory:",
	})
	test.AssertNotError(t, err, "Failed to create PA")

	// Test for invalid identifier type
	identifier := core.AcmeIdentifier{Type: "ip", Value: "example.com"}
	err = pa.WillingToIssue(identifier)
	_, ok := err.(InvalidIdentifierError)
	if !ok {
		t.Error("Identifier was not correctly forbidden: ", identifier)
	}

	// Test syntax errors
	for _, domain := range shouldBeSyntaxError {
		identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: domain}
		err := pa.WillingToIssue(identifier)
		_, ok := err.(SyntaxError)
		if !ok {
			t.Error("Identifier was not correctly forbidden: ", identifier, err)
		}
	}

	// Test public suffix matching
	for _, domain := range shouldBeNonPublic {
		identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: domain}
		err := pa.WillingToIssue(identifier)
		_, ok := err.(NonPublicError)
		if !ok {
			t.Error("Identifier was not correctly forbidden: ", identifier, err)
		}
	}

	// Test blacklisting
	for _, domain := range shouldBeBlacklisted {
		identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: domain}
		err := pa.WillingToIssue(identifier)
		_, ok := err.(BlacklistedError)
		if !ok {
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

type PADBMock struct{}

func (padb PADBMock) externalCertDataForFQDN(fqdn string) ([]core.ExternalCert, error) {
	spkiBytes, err := ioutil.ReadFile("test/external-cert-pubkey.der")
	if err != nil {
		return nil, err
	}
	if fqdn == "mail.eff.org" {
		return []core.ExternalCert{
			core.ExternalCert{
				SHA1:   "fake fingerprint!",
				Issuer: "Some Other CA",
				SPKI:   spkiBytes,
				EV:     false,
			},
		}, nil
	} else if fqdn == "ev.example.com" {
		return []core.ExternalCert{
			core.ExternalCert{
				SPKI: spkiBytes,
				EV:   true,
			},
			core.ExternalCert{
				SPKI: spkiBytes,
				EV:   false,
			},
		}, nil
	}
	return []core.ExternalCert{}, nil
}

func TestChallengesFor(t *testing.T) {
	pa, err := NewPolicyAuthorityImpl(Config{
		Driver: "sqlite3",
		Name:   ":memory:",
	})
	test.AssertNotError(t, err, "Failed to create PA")
	pa.padb = PADBMock{}

	challenges, combinations := pa.ChallengesFor(core.AcmeIdentifier{})

	if len(challenges) != 3 || challenges[0].Type != core.ChallengeTypeSimpleHTTP ||
		challenges[1].Type != core.ChallengeTypeDVSNI ||
		challenges[2].Type != core.ChallengeTypeDNS {
		t.Error("Incorrect challenges returned")
	}
	if len(combinations) != 3 || combinations[0][0] != 0 || combinations[1][0] != 1 {
		t.Error("Incorrect combinations returned")
	}
}

func TestChallengesForExistingDVCert(t *testing.T) {
	pa, err := NewPolicyAuthorityImpl(Config{
		Driver: "sqlite3",
		Name:   ":memory:",
	})
	test.AssertNotError(t, err, "Failed to create PA")
	pa.padb = PADBMock{}

	challenges, combinations := pa.ChallengesFor(core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: "mail.eff.org",
	})
	fmt.Println("XYZ", challenges)
	fmt.Println("RTU", combinations)
	test.Assert(t, len(challenges) == 4, "incorrect number of challenges")
	if len(challenges) != 4 {
		return
	}
	popChallengeIndex := 3
	popChallenge := challenges[popChallengeIndex]
	// Verify that each challenge combination entry contains the POP challenge.
	for _, combo := range combinations {
		containsPOP := false
		for _, challengeIndex := range combo {
			if challengeIndex == popChallengeIndex {
				containsPOP = true
			}
		}
		test.Assert(t, containsPOP, "Challenge combinations did not contain POP challenge")
	}
	test.Assert(t, popChallenge.Type == core.ChallengeTypeProofOfPosession, "incorrect challenge type")
	test.Assert(t, popChallenge.Status == core.StatusPending, "challenge not pending")
	test.Assert(t, popChallenge.Nonce != "", "empty nonce")
	test.Assert(t, popChallenge.Alg == "RS256", "wrong algorithm")
	test.Assert(t, len(popChallenge.Hints.CertFingerprints) == 1, "wrong number of certFingerprints")
	test.Assert(t, popChallenge.Hints.CertFingerprints[0] == "fake fingerprint", "wrong number of certFingerprints")
	test.Assert(t, len(popChallenge.Hints.Issuers) == 1, "wrong number of issuers")
	test.Assert(t, popChallenge.Hints.Issuers[0] == "Some Other CA", "wrong issuer")
}

func TestChallengesForExistingEVCert(t *testing.T) {
	pa, err := NewPolicyAuthorityImpl(Config{
		Driver: "sqlite3",
		Name:   ":memory:",
	})
	test.AssertNotError(t, err, "Failed to create PA")
	pa.padb = PADBMock{}

	challenges, combinations := pa.ChallengesFor(core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: "ev.example.com",
	})
	test.Assert(t, len(challenges) == 0, "incorrect number of challenges")
	test.Assert(t, len(combinations) == 0, "incorrect number of challenge combinations")
}
