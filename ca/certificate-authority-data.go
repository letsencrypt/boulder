// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ca

import (
	"errors"
	"time"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"

	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
)

// CertificateAuthorityDatabaseImpl represents a database used by the CA; it
// enforces transaction semantics, and is effectively single-threaded.
type CertificateAuthorityDatabaseImpl struct {
	log      *blog.AuditLogger
	dbMap    *gorp.DbMap
	activeTx *gorp.Transaction
}

type SerialNumber struct {
	ID          int       `db:"id"`
	Number      int64     `db:"number"`
	LastUpdated time.Time `db:"lastUpdated"`
}

// NewCertificateAuthorityDatabaseImpl constructs a Database for the
// Certificate Authority.
func NewCertificateAuthorityDatabaseImpl(driver string, name string) (cadb core.CertificateAuthorityDatabase, err error) {
	logger := blog.GetAuditLogger()

	dbMap, err := sa.NewDbMap(driver, name)
	if err != nil {
		return nil, err
	}

	dbMap.AddTableWithName(SerialNumber{}, "serialNumber").SetKeys(true, "ID")

	cadb = &CertificateAuthorityDatabaseImpl{
		dbMap: dbMap,
		log:   logger,
	}
	return cadb, nil
}

// createTablesIfNotExist builds the database tables and inserts the initial
// state, if the tables do not already exist. It is not an error for the tables
// to already exist.
func (cadb *CertificateAuthorityDatabaseImpl) CreateTablesIfNotExists() (err error) {
	// Create serial number table
	err = cadb.dbMap.CreateTablesIfNotExists()
	if err != nil {
		return
	}

	// Initialize the serial number
	err = cadb.dbMap.Insert(&SerialNumber{ID: 1, Number: 1, LastUpdated: time.Now()})
	return
}

// Begin starts a Database transaction. There can only be one in this object
// at a time.
func (cadb *CertificateAuthorityDatabaseImpl) Begin() (err error) {
	if cadb.activeTx != nil {
		err = errors.New("Transaction already open")
		return
	}
	cadb.activeTx, err = cadb.dbMap.Begin()
	return
}

// Commit makes permanent a database transaction; there must be an active
// transaction when called.
func (cadb *CertificateAuthorityDatabaseImpl) Commit() (err error) {
	if cadb.activeTx == nil {
		err = errors.New("Transaction already closed")
		return
	}
	err = cadb.activeTx.Commit()
	cadb.activeTx = nil
	return
}

// Rollback cancels the ongoing database transaction; there must be an active
// transaction when called.
func (cadb *CertificateAuthorityDatabaseImpl) Rollback() (err error) {
	if cadb.activeTx == nil {
		err = errors.New("Transaction already closed")
		return
	}
	err = cadb.activeTx.Rollback()
	cadb.activeTx = nil
	return
}

// IncrementAndGetSerial returns the next-available serial number, incrementing
// it in the database before returning. There must be an active transaction to
// call this method. Callers should Begin the transaction, call this method,
// perform any other work, and Commit at the end once the certificate is issued.
func (cadb *CertificateAuthorityDatabaseImpl) IncrementAndGetSerial() (val int64, err error) {
	if cadb.activeTx == nil {
		err = errors.New("No transaction open")
		return
	}

	rowObj, err := cadb.activeTx.Get(SerialNumber{}, 1)
	if err != nil {
		cadb.activeTx.Rollback()
		return
	}

	row := rowObj.(*SerialNumber)
	val = row.Number
	row.Number = val + 1

	_, err = cadb.activeTx.Update(row)
	if err != nil {
		cadb.activeTx.Rollback()
		return
	}

	return
}
