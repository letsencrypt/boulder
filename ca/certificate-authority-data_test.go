// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ca

import (
	"testing"

	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/mattn/go-sqlite3"
	"github.com/letsencrypt/boulder/test"
)

const badDriver = "nothing"
const badFilename = "/doesnotexist/nofile"
const sqliteDriver = "sqlite3"
const sqliteName = ":memory:"

func TestConstruction(t *testing.T) {
	// Successful case
	_, err := NewCertificateAuthorityDatabaseImpl(sqliteDriver, sqliteName)
	test.AssertNotError(t, err, "Could not construct CA DB")

	// Covers "sql.Open" error
	_, err = NewCertificateAuthorityDatabaseImpl(badDriver, sqliteName)
	test.AssertError(t, err, "Should have failed construction")

	// Covers "db.Ping" error
	_, err = NewCertificateAuthorityDatabaseImpl(sqliteDriver, badFilename)
	test.AssertError(t, err, "Should have failed construction")
}

func TestGetSetSequenceOutsideTx(t *testing.T) {
	cadb, err := NewCertificateAuthorityDatabaseImpl(sqliteDriver, sqliteName)
	test.AssertNotError(t, err, "Could not construct CA DB")

	err = cadb.CreateTablesIfNotExists()
	test.AssertNotError(t, err, "Could not construct tables")

	_, err = cadb.IncrementAndGetSerial(nil)
	test.AssertError(t, err, "Not permitted")

	tx, err := cadb.GetDbMap().Begin()
	test.AssertNotError(t, err, "Could not begin")
	tx.Commit()
	_, err = cadb.IncrementAndGetSerial(tx)
	test.AssertError(t, err, "Not permitted")

	tx2, err := cadb.GetDbMap().Begin()
	test.AssertNotError(t, err, "Could not begin")
	tx2.Rollback()
	_, err = cadb.IncrementAndGetSerial(tx2)
	test.AssertError(t, err, "Not permitted")
}

func TestGetSetSequenceNumber(t *testing.T) {
	cadb, err := NewCertificateAuthorityDatabaseImpl(sqliteDriver, sqliteName)
	test.AssertNotError(t, err, "Could not construct CA DB")

	err = cadb.CreateTablesIfNotExists()
	test.AssertNotError(t, err, "Could not construct tables")

	tx, err := cadb.GetDbMap().Begin()
	test.AssertNotError(t, err, "Could not begin")

	num, err := cadb.IncrementAndGetSerial(tx)
	test.AssertNotError(t, err, "Could not get number")

	num2, err := cadb.IncrementAndGetSerial(tx)
	test.AssertNotError(t, err, "Could not get number")
	test.Assert(t, num+1 == num2, "Numbers should be incrementing")

	err = tx.Commit()
	test.AssertNotError(t, err, "Could not commit")
}
