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

func TestInvalidDSN(t *testing.T) {
	_, err := NewDbMap("mysql", "invalid")
	test.AssertError(t, err, "DB connect string missing the slash separating the database name")
}
