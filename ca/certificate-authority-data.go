// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ca

import (
	"database/sql"
	"errors"
	"time"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

// CertificateAuthorityDatabaseImpl represents a database used by the CA; it
// enforces transaction semantics, and is effectively single-threaded.
type CertificateAuthorityDatabaseImpl struct {
	log      *blog.AuditLogger
	db       *sql.DB
	activeTx *sql.Tx
}

// NewCertificateAuthorityDatabaseImpl constructs a Database for the
// Certificate Authority.
func NewCertificateAuthorityDatabaseImpl(driver string, name string) (cadb core.CertificateAuthorityDatabase, err error) {
	logger := blog.GetAuditLogger()

	db, err := sql.Open(driver, name)
	if err != nil {
		return
	}
	if err = db.Ping(); err != nil {
		return
	}

	cadb = &CertificateAuthorityDatabaseImpl{
		db:  db,
		log: logger,
	}

	err = createTablesIfNotExist(db)
	return
}

// createTablesIfNotExist builds the database tables and inserts the initial
// state, if the tables do not already exist. It is not an error for the tables
// to already exist.
func createTablesIfNotExist(db *sql.DB) (err error) {
	tx, err := db.Begin()
	if err != nil {
		return
	}

	// Create serial number table
	_, err = tx.Exec("CREATE TABLE serialNumber (id INTEGER, number INTEGER, lastUpdated DATETIME);")
	if err != nil {
		// If the table exists, exit early
		tx.Rollback()
		return nil
	}

	// Initialize the serial number
	_, err = tx.Exec("INSERT INTO serialNumber (id, number, lastUpdated) VALUES (1, 1, ?);", time.Now())
	if err != nil {
		tx.Rollback()
		return
	}

	err = tx.Commit()
	return
}

// Begin starts a Database transaction. There can only be one in this object
// at a time.
func (cadb *CertificateAuthorityDatabaseImpl) Begin() (err error) {
	if cadb.activeTx != nil {
		err = errors.New("Transaction already open")
		return
	}
	cadb.activeTx, err = cadb.db.Begin()
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
func (cadb *CertificateAuthorityDatabaseImpl) IncrementAndGetSerial() (val int, err error) {
	if cadb.activeTx == nil {
		err = errors.New("No transaction open")
		return
	}

	row := cadb.activeTx.QueryRow("SELECT number FROM serialNumber LIMIT 1;")

	err = row.Scan(&val)
	if err != nil {
		cadb.activeTx.Rollback()
		return
	}

	_, err = cadb.activeTx.Exec("UPDATE serialNumber SET number=?, lastUpdated=? WHERE id=1", val+1, time.Now())
	if err != nil {
		cadb.activeTx.Rollback()
		return
	}

	return
}
