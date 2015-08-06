// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package policy

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestAdd(t *testing.T) {
	p, err := NewPolicyAuthorityDatabaseImpl("sqlite3", ":memory:")
	test.AssertNotError(t, err, "Couldn't create PADB")
	err = p.AddRule("a.bracewel.net", blacklisted)
	test.AssertNotError(t, err, "Failed to add blacklist rule")
	err = p.AddRule("b.bracewel.net", whitelisted)
	test.AssertNotError(t, err, "Failed to add whitelist rule")
	err = p.AddRule("b.bracewel.net", whitelisted)
	test.AssertError(t, err, "Didn't error on duplicate rule")
}

func TestGet(t *testing.T) {
	p, err := NewPolicyAuthorityDatabaseImpl("sqlite3", ":memory:")
	test.AssertNotError(t, err, "Couldn't create PADB")
	err = p.AddRule("bracewel.net", blacklisted)
	test.AssertNotError(t, err, "Failed to add blacklist rule")
	err = p.AddRule("%a.bracewel.net", whitelisted)
	test.AssertNotError(t, err, "Failed to add blacklist rule")
	err = p.AddRule("%ba.bracewel.net", whitelisted)
	test.AssertNotError(t, err, "Failed to add blacklist rule")

	err = p.CheckRules("abba.bracewel.net")
	test.AssertNotError(t, err, "Hostname should be whitelisted")
	err = p.CheckRules("bracewel.net")
	test.AssertError(t, err, "Hostname should be blacklisted")

	err = p.AddRule("%bracewel.net", blacklisted)
	test.AssertNotError(t, err, "Failed to add blacklist rule")
	err = p.CheckRules("abba.bracewel.net")
	test.AssertNotError(t, err, "Hostname should be whitelisted")
}
