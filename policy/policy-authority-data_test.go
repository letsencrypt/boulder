// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package policy

import (
	"fmt"
	"testing"

	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"

	gorp "gopkg.in/gorp.v1"
)

func padbImpl(t *testing.T) (*AuthorityDatabaseImpl, func()) {
	dbMap, err := sa.NewDbMap(vars.DBConnPolicy)
	test.AssertNotError(t, err, "Could not construct dbMap")

	padb, err := NewAuthorityDatabaseImpl(dbMap)
	test.AssertNotError(t, err, "Couldn't create PADB")

	cleanUp := test.ResetPolicyTestDatabase(t)

	return padb, cleanUp
}

func TestLoadAndDumpRules(t *testing.T) {
	p, cleanup := padbImpl(t)
	defer cleanup()

	load := RuleSet{
		Blacklist: []BlacklistRule{
			{
				Host: "bad.com",
			},
		},
		Whitelist: []WhitelistRule{
			{
				Host: "good.bad.com",
			},
		},
	}
	err := p.LoadRules(load)
	test.AssertNotError(t, err, "Couldn't load rules")

	dumped, err := p.DumpRules()
	test.AssertNotError(t, err, "Couldn't dump rules")
	test.AssertEquals(t, len(dumped.Blacklist), 1)
	test.AssertEquals(t, len(dumped.Whitelist), 1)

	test.AssertEquals(t, dumped.Whitelist[0], load.Whitelist[0])
	test.AssertEquals(t, dumped.Blacklist[0], load.Blacklist[0])
}

// An implementation of the gorpDbMap interface that always returns an error
// from SelectOne.
type failureDB struct{}

func (f *failureDB) AddTableWithName(interface{}, string) *gorp.TableMap {
	return nil // not implemented
}

func (f *failureDB) Begin() (*gorp.Transaction, error) {
	return nil, nil // not implemented
}
func (f *failureDB) SelectOne(interface{}, string, ...interface{}) error {
	return fmt.Errorf("DB failure")
}

func (f *failureDB) Select(interface{}, string, ...interface{}) ([]interface{}, error) {
	return nil, nil // not implemented
}

func TestBlacklistError(t *testing.T) {
	p, err := NewAuthorityDatabaseImpl(&failureDB{})
	test.AssertNotError(t, err, "Couldn't make PA")
	err = p.CheckHostLists("bad.com", false)
	test.AssertEquals(t, err, errDBFailure)
}

func TestBlacklist(t *testing.T) {
	p, cleanup := padbImpl(t)
	defer cleanup()

	err := p.LoadRules(RuleSet{
		Blacklist: []BlacklistRule{
			{
				Host: "bad.com",
			},
		},
		Whitelist: []WhitelistRule{
			{
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
			{
				Host: "bad.com",
			},
		},
		Whitelist: []WhitelistRule{
			{
				Host: "good.bad.com",
			},
			{
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
