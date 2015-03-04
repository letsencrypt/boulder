// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package boulder

import (
	"crypto/sha256"
	"database/sql"
)

type SQLStorageAuthority struct {
	db     *sql.DB
	bucket map[string]interface{} // XXX included only for backward compat
}

func digest256(data []byte) []byte {
	d := sha256.New()
	d.Write(data)
	return d.Sum(nil)
}

func NewSQLStorageAuthority(driver string, name string) (ssa *SQLStorageAuthority, err error) {
	db, err := sql.Open(driver, name)
	if err != nil {
		return
	}
	if err = db.Ping(); err != nil {
		return
	}

	ssa = &SQLStorageAuthority{
		db:     db,
		bucket: make(map[string]interface{}),
	}
	return
}

func (ssa *SQLStorageAuthority) InitTables() (err error) {
	// Create certificates table
	query := "CREATE TABLE certificates (location INTEGER, digest TEXT, value BLOB);"
	_, err = ssa.db.Exec(query)
	return
}

// DEPRECATED
func (ssa *SQLStorageAuthority) Update(key string, value interface{}) (err error) {
	ssa.bucket[key] = value
	return nil
}

// DEPRECATED
func (ssa *SQLStorageAuthority) Get(key string) (value interface{}, err error) {
	value, ok := ssa.bucket[key]
	if !ok {
		err = NotFoundError("Unknown storage key")
	}
	return
}

func (ssa *SQLStorageAuthority) AddCertificate(cert []byte) (id string, err error) {
	// Manually set the index, to avoid AUTOINCREMENT issues
	var location int64
	var scanTarget sql.NullInt64
	err = ssa.db.QueryRow("SELECT max(location) FROM certificates").Scan(&scanTarget)
	switch {
	case !scanTarget.Valid:
		location = 0
	case err != nil:
		return
	default:
		location += scanTarget.Int64 + 1
	}

	id = fingerprint256(cert)
	query := "INSERT INTO certificates (location, digest, value) VALUES (?,?,?);"
	_, err = ssa.db.Exec(query, location, id, cert)
	return
}

func (ssa *SQLStorageAuthority) GetCertificate(id string) (cert []byte, err error) {
	err = ssa.db.QueryRow("SELECT value FROM certificates WHERE digest = ?", id).Scan(&cert)
	return
}
