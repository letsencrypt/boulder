// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package policy

import (
	"testing"

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
)

func TestLoadAndDump(t *testing.T) {
	p, err := NewPolicyAuthorityDatabaseImpl(dbConnStr)
	test.AssertNotError(t, err, "Couldn't create PADB")

	err = p.LoadRules([]DomainRule{rA, rB, rC})
	test.AssertNotError(t, err, "Couldn't load rules")

	r, err := p.DumpRules()
	test.AssertNotError(t, err, "Couldn't dump rules")

	test.AssertEquals(t, len(r), 3)
}

func TestGet(t *testing.T) {
	p, err := NewPolicyAuthorityDatabaseImpl(dbConnStr)
	test.AssertNotError(t, err, "Couldn't create PADB")

	err = p.LoadRules([]DomainRule{rA, rB, rC})
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

	err = p.CheckRules("e.d.c.com", false)
	test.AssertError(t, err, "Hostname should be blacklisted")
}
