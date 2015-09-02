// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package policy

import (
	"testing"

	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
)

func padbImpl(t *testing.T) (*PolicyAuthorityDatabaseImpl, func()) {
	dbMap, err := sa.NewDbMap(dbConnStr)
	test.AssertNotError(t, err, "Could not construct dbMap")

	padb, err := NewPolicyAuthorityDatabaseImpl(dbMap)
	test.AssertNotError(t, err, "Couldn't create PADB")

	cleanUp := test.ResetTestDatabase(t, dbMap.Db)

	return padb, cleanUp
}

func TestBlacklist(t *testing.T) {
	p, cleanup := padbImpl(t)
	defer cleanup()

	err := p.LoadRules(RuleSet{
		Blacklist: []BlacklistRule{
			BlacklistRule{
				Host: "bad.com",
			},
		},
		Whitelist: []WhitelistRule{
			WhitelistRule{
				Host: "good.bad.com",
			},
		},
	})
	test.AssertNotError(t, err, "Couldn't load rules")

	err = p.CheckHostLists("bad.com", false)
	test.AssertError(t, err, "Hostname should be blacklisted")
	err = p.CheckHostLists("still.bad.com", false)
	test.AssertError(t, err, "Hostname should be blacklisted")
	err = p.CheckHostLists("badminton.com", false)
	test.AssertNotError(t, err, "Hostname shouldn't be blacklisted")
	// Whitelisted subdomain of blacklisted root should still be blacklsited
	err = p.CheckHostLists("good.bad.com", true)
	test.AssertError(t, err, "Blacklist should beat whitelist")
	// Not blacklisted
	err = p.CheckHostLists("good.com", false)
	test.AssertNotError(t, err, "Hostname shouldn't be blacklisted")
}

func TestWhitelist(t *testing.T) {
	p, cleanup := padbImpl(t)
	defer cleanup()

	err := p.LoadRules(RuleSet{
		Blacklist: []BlacklistRule{
			BlacklistRule{
				Host: "bad.com",
			},
		},
		Whitelist: []WhitelistRule{
			WhitelistRule{
				Host: "good.bad.com",
			},
			WhitelistRule{
				Host: "good.com",
			},
		},
	})
	test.AssertNotError(t, err, "Couldn't load rules")

	err = p.CheckHostLists("bad.com", true)
	test.AssertError(t, err, "Hostname should be blacklisted")
	// Whitelisted subdomain of blacklisted root should still be blacklsited
	err = p.CheckHostLists("good.bad.com", true)
	test.AssertError(t, err, "Blacklist should beat whitelist")
	// Non-existent domain should fail
	err = p.CheckHostLists("not-good.com", true)
	test.AssertError(t, err, "Hostname isn't on whitelist")
	// Whitelisted
	err = p.CheckHostLists("good.com", true)
	test.AssertNotError(t, err, "Hostname is on whitelist")
}
