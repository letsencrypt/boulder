// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ca

import (
	"testing"
	"time"

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

	// This row is required to exist for caDBImpl to work correctly. We
	// can no longer use dbMap.Insert(&SerialNumber{...}) for this
	// because gorp will ignore the ID and insert a new row at a new
	// autoincrement id.
	// TODO(jmhodges): gen ids flickr-style, no row needed a head of time
	_, err = dbMap.Db.Exec("insert into serialNumber (id, number, lastUpdated) VALUES (?, ?, ?)", 1, 1, time.Now())
	if err != nil {
		t.Fatalf("unable to create the serial number row: %s", err)
	}
	return cadb, cleanUp
}
