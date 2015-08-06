// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sa

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestNewDbMap(t *testing.T) {
	_, err := NewDbMap("", "")
	test.AssertError(t, err, "Nil not permitted.")

	_, err = NewDbMap("sqlite3", "/not/a/file")
	test.AssertError(t, err, "Shouldn't have found a DB.")

	_, err = NewDbMap("sqlite3", ":memory:")
	test.AssertNotError(t, err, "Should have constructed a DB.")
}

func TestForgottenDialect(t *testing.T) {
	bkup := dialectMap["sqlite3"]
	dialectMap["sqlite3"] = ""
	defer func() { dialectMap["sqlite3"] = bkup }()

	_, err := NewDbMap("sqlite3", ":memory:")
	test.AssertError(t, err, "Shouldn't have found the dialect")
}

func TestMySQLInvalidDSN(t *testing.T) {
	_, err := NewDbMap("mysql", "invalid")
	test.AssertError(t, err, "DB connect string missing the slash separating the database name")
}

func TestMySQLFixDSN(t *testing.T) {
	tests := []struct {
		in  string
		out string
		err bool
	}{
		{
			"invalid",
			"",
			true,
		},
		{
			"",
			"",
			true,
		},
		{
			"/boulder?parseTime=true",
			"/boulder?parseTime=true",
			false,
		},
		{
			"/boulder",
			"/boulder?parseTime=true",
			false,
		},
		{
			"/boulder?parseTime=false",
			"/boulder?parseTime=true",
			false,
		},
		{
			"/boulder?other=value",
			"/boulder?other=value&parseTime=true",
			false,
		},
		{
			"yes:my@pass(word)/looks?like=a&dsn=true@tcp(localhost:3306)/boulder",
			"yes:my@pass(word)/looks?like=a&dsn=true@tcp(localhost:3306)/boulder?parseTime=true",
			false,
		},
	}
	for i := range tests {
		out, err := fixMysqlDSN(tests[i].in)
		if tests[i].err {
			test.AssertError(t, err, "DSN is malformed")
		} else {
			test.AssertNotError(t, err, "DSN is valid")
			test.AssertEquals(t, tests[i].out, out)
		}
	}
}
