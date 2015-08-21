// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ca

import (
	"fmt"
	"time"

	blog "github.com/letsencrypt/boulder/log"

	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
)

// CertificateAuthorityDatabaseImpl represents a database used by the CA; it
// enforces transaction semantics, and is effectively single-threaded.
type CertificateAuthorityDatabaseImpl struct {
	log   *blog.AuditLogger
	dbMap *gorp.DbMap
}

// SerialNumber defines the database table used to hold the serial number.
type SerialNumber struct {
	ID          int       `db:"id"`
	Number      int64     `db:"number"`
	LastUpdated time.Time `db:"lastUpdated"`
}

// NewCertificateAuthorityDatabaseImpl constructs a Database for the
// Certificate Authority.
func NewCertificateAuthorityDatabaseImpl(dbMap *gorp.DbMap) (cadb *CertificateAuthorityDatabaseImpl, err error) {
	logger := blog.GetAuditLogger()

	dbMap.AddTableWithName(SerialNumber{}, "serialNumber").SetKeys(true, "ID")

	cadb = &CertificateAuthorityDatabaseImpl{
		dbMap: dbMap,
		log:   logger,
	}
	return cadb, nil
}

// Begin starts a transaction at the GORP wrapper.
func (cadb *CertificateAuthorityDatabaseImpl) Begin() (*gorp.Transaction, error) {
	return cadb.dbMap.Begin()
}

// IncrementAndGetSerial returns the next-available serial number, incrementing
// it in the database before returning. There must be an active transaction to
// call this method. Callers should Begin the transaction, call this method,
// perform any other work, and Commit at the end once the certificate is issued.
func (cadb *CertificateAuthorityDatabaseImpl) IncrementAndGetSerial(tx *gorp.Transaction) (val int64, err error) {
	if tx == nil {
		err = fmt.Errorf("No transaction given")
		return
	}

	rowObj, err := tx.Get(SerialNumber{}, 1)
	if err != nil {
		return
	}

	row, ok := rowObj.(*SerialNumber)
	if !ok {
		err = fmt.Errorf("No serial number found. This is a serious issue")
		return
	}

	val = row.Number
	row.Number = val + 1

	_, err = tx.Update(row)
	if err != nil {
		return
	}

	return
}
