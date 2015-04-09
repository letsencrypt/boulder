// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ca

import (
  "database/sql"
  "errors"

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

func  (cadb *CertificateAuthorityDatabaseImpl) GetNextNumber() (val int, err error) {
  if cadb.activeTx == nil {
    err = errors.New("No transaction open")
    return
  }

  return 1, nil
}

func  (cadb *CertificateAuthorityDatabaseImpl) IncrementNumber() (err error) {
  if cadb.activeTx == nil {
    err = errors.New("No transaction open")
    return
  }

  return nil
}


