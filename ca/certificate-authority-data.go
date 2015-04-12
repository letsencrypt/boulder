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

type CertificateAuthorityDatabaseImpl struct {
  log       *blog.AuditLogger
  db        *sql.DB
  activeTx  *sql.Tx
}

func NewCertificateAuthorityDatabaseImpl(logger *blog.AuditLogger, driver string, name string) (cadb core.CertificateAuthorityDatabase, err error) {
  if logger == nil {
    err = errors.New("Nil logger not permitted")
    return
  }

  db, err := sql.Open(driver, name)
  if err != nil {
    return
  }
  if err = db.Ping(); err != nil {
    return
  }

  cadb = &CertificateAuthorityDatabaseImpl{
    db:     db,
    log:    logger,
  }

  err = createTablesIfNotExist(db)
  return
}

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

func (cadb *CertificateAuthorityDatabaseImpl) Begin() (err error) {
  if cadb.activeTx != nil {
    err = errors.New("Transaction already open")
    return
  }
  cadb.activeTx, err = cadb.db.Begin()
  return
}

func (cadb *CertificateAuthorityDatabaseImpl) Commit() (err error) {
  if cadb.activeTx == nil {
    err = errors.New("Transaction already closed")
    return
  }
  err = cadb.activeTx.Commit()
  cadb.activeTx = nil
  return
}

func (cadb *CertificateAuthorityDatabaseImpl) Rollback() (err error) {
  if cadb.activeTx == nil {
    err = errors.New("Transaction already closed")
    return
  }
  err = cadb.activeTx.Rollback()
  cadb.activeTx = nil
  return
}

func  (cadb *CertificateAuthorityDatabaseImpl) IncrementAndGetSerial() (val int, err error) {
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

  val = val + 1

  _, err = cadb.activeTx.Exec("UPDATE serialNumber SET number=?, lastUpdated=? WHERE id=1", val, time.Now())
  if err != nil {
    cadb.activeTx.Rollback()
    return
  }

  return
}



