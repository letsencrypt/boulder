// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ca

import (
	"testing"

	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
)

func TestGetSetSequenceOutsideTx(t *testing.T) {
	cadb, cleanUp := caDBImpl(t)
	defer cleanUp()
	tx, err := cadb.Begin()
	test.AssertNotError(t, err, "Could not begin")
	tx.Commit()
	_, err = cadb.IncrementAndGetSerial(tx)
	test.AssertError(t, err, "Not permitted")

	tx2, err := cadb.Begin()
	test.AssertNotError(t, err, "Could not begin")
	tx2.Rollback()
	_, err = cadb.IncrementAndGetSerial(tx2)
	test.AssertError(t, err, "Not permitted")
}

func TestGetSetSequenceNumber(t *testing.T) {
	cadb, cleanUp := caDBImpl(t)
	defer cleanUp()
	tx, err := cadb.Begin()
	test.AssertNotError(t, err, "Could not begin")

	num, err := cadb.IncrementAndGetSerial(tx)
	test.AssertNotError(t, err, "Could not get number")

	num2, err := cadb.IncrementAndGetSerial(tx)
	test.AssertNotError(t, err, "Could not get number")
	test.Assert(t, num+1 == num2, "Numbers should be incrementing")

	err = tx.Commit()
	test.AssertNotError(t, err, "Could not commit")
}

func TestRollbackSequenceStability(t *testing.T) {
	cadb, cleanUp := caDBImpl(t)
	defer cleanUp()

	// OK, we're starting up. We're gonna issue a serial number
	// successfully.
	tx1, err := cadb.Begin()
	test.AssertNotError(t, err, "Could not begin")

	num1, err := cadb.IncrementAndGetSerial(tx1)
	test.AssertNotError(t, err, "Could not get number")

	err = tx1.Commit()
	test.AssertNotError(t, err, "Could not commit")

	// Great. Now we're going to try to issue, but the HSM
	// balked, or we took a reset, or something.

	tx2, err := cadb.Begin()
	test.AssertNotError(t, err, "Could not begin")

	num2, err := cadb.IncrementAndGetSerial(tx2)
	test.AssertNotError(t, err, "Could not get number")

	// Pretend we had an HSM failure, or whatever
	tx2.Rollback()


	// OK, all is fixed now. Try again to re-issue.
	tx3, err := cadb.Begin()
	test.AssertNotError(t, err, "Could not begin again")

	num3, err := cadb.IncrementAndGetSerial(tx3)
	test.AssertNotError(t, err, "Could not get number again")

	// Commit for safety's sake, to make sure we can.
	err = tx3.Commit()
	test.AssertNotError(t, err, "Could not commit")


	// num3 and num2 should be identical, because we never used num2.
	// If they aren't identical, then we would, in a failure scenario,
	// skip a certificate serial index.
	test.Assert(t, num2 == num3, "Numbers should be identical, because we rolled back")

	// Just to double-check:
	// num3 and num1 should be one apart from each other, indicating
	// that there was no gap.
	test.Assert(t, num1+1 == num3, "Numbers should be incrementing")
}

func caDBImpl(t *testing.T) (*CertificateAuthorityDatabaseImpl, func()) {
	dbMap, err := sa.NewDbMap(caDBConnStr)
	if err != nil {
		t.Fatalf("Could not construct dbMap: %s", err)
	}

	cadb, err := NewCertificateAuthorityDatabaseImpl(dbMap)
	if err != nil {
		t.Fatalf("Could not construct CA DB: %s", err)
	}

	cleanUp := test.ResetTestDatabase(t, dbMap.Db)
	return cadb, cleanUp
}
