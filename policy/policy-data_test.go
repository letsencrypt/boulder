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

var (
	rA = DomainRule{
		Host: "a.com",
		Type: whitelisted,
	}
	rB = DomainRule{
		Host: "b.com",
		Type: blacklisted,
	}
	rC = DomainRule{
		Host: "d.c.com",
		Type: blacklisted,
	}
	rD = DomainRule{
		Host: "a.d.com",
		Type: whitelisted,
	}
	rE = DomainRule{
		Host: "d.com",
		Type: blacklisted,
	}
	rM1 = DomainRule{
		Host: "mail.com",
		Type: whitelisted,
	}
	rM2 = DomainRule{
		Host: "mailthing.com",
		Type: blacklisted,
	}
	rM3 = DomainRule{
		Host: "mailbox.com",
		Type: blacklisted,
	}
)

func TestLoadAndDump(t *testing.T) {
	p, cleanup := padbImpl(t)
	defer cleanup()

	err := p.LoadRules([]DomainRule{rA, rB, rC})
	test.AssertNotError(t, err, "Couldn't load rules")

	r, err := p.DumpRules()
	test.AssertNotError(t, err, "Couldn't dump rules")

	test.AssertEquals(t, len(r), 3)
}

func TestBoring(t *testing.T) {
	p, cleanup := padbImpl(t)
	defer cleanup()

	err := p.LoadRules([]DomainRule{rM1})
	test.AssertNotError(t, err, "Couldn't load rules")

	err = p.CheckWhitelist("mailbox.com")
	test.AssertNotError(t, err, "BAD")
}

func TestGet(t *testing.T) {
	p, cleanup := padbImpl(t)
	defer cleanup()

	err := p.LoadRules([]DomainRule{rA, rB, rC, rD, rE})
	test.AssertNotError(t, err, "Couldn't load rules")

	err = p.CheckRules("b.com", false)
	test.AssertError(t, err, "Hostname should be blacklisted")
	err = p.CheckRules("a.b.com", false)
	test.AssertError(t, err, "Hostname should be blacklisted")

	err = p.CheckRules("a.com", false)
	test.AssertNotError(t, err, "Hostname should be whitelisted")
	err = p.CheckRules("a.a.com", false)
	test.AssertNotError(t, err, "Hostname should be whitelisted")

	err = p.CheckRules("a.com", true)
	test.AssertNotError(t, err, "Hostname should be whitelisted")
	err = p.CheckRules("a.a.com", true)
	test.AssertError(t, err, "Hostname isn't explicitly whitelisted")

	err = p.CheckRules("ab.com", false)
	test.AssertNotError(t, err, "Hostname should not be blacklisted")
	err = p.CheckRules(".b.com", false)
	test.AssertError(t, err, "Hostname should be blacklisted")

	err = p.CheckRules("a.d.com", false)
	test.AssertNotError(t, err, "Hostname shouldn't be blacklisted")
	err = p.CheckRules("d.com", false)
	test.AssertError(t, err, "Hostname should be blacklisted")

	err = p.CheckRules("e.d.c.com", false)
	test.AssertError(t, err, "Hostname should be blacklisted")
}

func padbImpl(t *testing.T) (*PolicyAuthorityDatabaseImpl, func()) {
	dbMap, err := sa.NewDbMap(dbConnStr)
	test.AssertNotError(t, err, "Could not construct dbMap")

	padb, err := NewPolicyAuthorityDatabaseImpl(dbMap)
	test.AssertNotError(t, err, "Couldn't create PADB")

	cleanUp := func() {
		if err := dbMap.TruncateTables(); err != nil {
			t.Fatalf("Could not truncate tables after the test: %s", err)
		}
		dbMap.Db.Close()
	}

	return padb, cleanUp
}
