// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ca

import (
  "testing"

  _ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/mattn/go-sqlite3"
  blog "github.com/letsencrypt/boulder/log"
  "github.com/letsencrypt/boulder/test"
)

const badDriver = "nothing"
const badFilename = "/doesnotexist/nofile"
const sqliteDriver = "sqlite3"
const sqliteName = ":memory:"

func TestConstruction(t *testing.T) {
  log, err := blog.Dial("", "", "tag")
  test.AssertNotError(t, err, "Could not construct audit logger")

  // Successful case
  _, err = NewCertificateAuthorityDatabaseImpl(log, sqliteDriver, sqliteName)
  test.AssertNotError(t, err, "Could not construct CA DB")

  // Covers "sql.Open" error
  _, err = NewCertificateAuthorityDatabaseImpl(log, badDriver, sqliteName)
  test.AssertError(t, err, "Should have failed construction")

  // Covers "db.Ping" error
  _, err = NewCertificateAuthorityDatabaseImpl(log, sqliteDriver, badFilename)
  test.AssertError(t, err, "Should have failed construction")

  // Ensures no nil pointer exception in logging
  _, err = NewCertificateAuthorityDatabaseImpl(nil, sqliteDriver, sqliteName)
  test.AssertError(t, err, "Should have failed construction")
}

func TestBeginCommit(t *testing.T) {
  log, err := blog.Dial("", "", "tag")
  test.AssertNotError(t, err, "Could not construct audit logger")

  cadb, err := NewCertificateAuthorityDatabaseImpl(log, sqliteDriver, sqliteName)
  test.AssertNotError(t, err, "Could not construct CA DB")

  err = cadb.Begin()
  test.AssertNotError(t, err, "Could not begin")

  err = cadb.Begin()
  test.AssertError(t, err, "Should have already begun")

  err = cadb.Commit()
  test.AssertNotError(t, err, "Could not commit")

  err = cadb.Commit()
  test.AssertError(t, err, "Should have already committed")

}

func TestGetSetSequenceOutsideTx(t *testing.T) {
  log, err := blog.Dial("", "", "tag")
  test.AssertNotError(t, err, "Could not construct audit logger")

  cadb, err := NewCertificateAuthorityDatabaseImpl(log, sqliteDriver, sqliteName)
  test.AssertNotError(t, err, "Could not construct CA DB")

  _, err = cadb.GetNextNumber()
  test.AssertError(t, err, "Not permitted")

  err = cadb.IncrementNumber()
  test.AssertError(t, err, "Not permitted")
}

func TestGetSetSequenceNumber(t *testing.T) {
  log, err := blog.Dial("", "", "tag")
  test.AssertNotError(t, err, "Could not construct audit logger")

  cadb, err := NewCertificateAuthorityDatabaseImpl(log, sqliteDriver, sqliteName)
  test.AssertNotError(t, err, "Could not construct CA DB")

  err = cadb.Begin()
  test.AssertNotError(t, err, "Could not begin")

  num, err := cadb.GetNextNumber()
  test.AssertNotError(t, err, "Could not get number")

  num2, err := cadb.GetNextNumber()
  test.AssertNotError(t, err, "Could not get number")
  test.Assert(t, num == num2, "Numbers should be the same")

  err = cadb.IncrementNumber()
  test.AssertNotError(t, err, "Could not get number")

  num3, err := cadb.GetNextNumber()
  test.AssertNotError(t, err, "Could not get number")
  test.Assert(t, num3 != num2, "Numbers should not be the same")

  num4, err := cadb.GetNextNumber()
  test.AssertNotError(t, err, "Could not get number")
  test.Assert(t, num4 == num3, "Numbers should be the same")

  err = cadb.Commit()
  test.AssertNotError(t, err, "Could not commit")
}