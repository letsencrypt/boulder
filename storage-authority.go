// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package boulder

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
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
	query := "CREATE TABLE certificates (sequence INTEGER, digest TEXT, value BLOB);"
	_, err = ssa.db.Exec(query)
	if err != nil {
		return
	}

	// Create pending authorizations table
	query = "CREATE TABLE pending_authz (id string, value BLOB)"
	_, err = ssa.db.Exec(query)
	if err != nil {
		return
	}

	// Create finalized authorizations table
	query = "CREATE TABLE authz (sequence INTEGER, id TEXT, digest TEXT, value BLOB)"
	_, err = ssa.db.Exec(query)
	return
}

func (ssa *SQLStorageAuthority) GetCertificate(id string) (cert []byte, err error) {
	err = ssa.db.QueryRow("SELECT value FROM certificates WHERE digest = ?", id).Scan(&cert)
	return
}

func statusIsPending(status AcmeStatus) bool {
	return status == StatusPending || status == StatusProcessing || status == StatusUnknown
}

func (ssa *SQLStorageAuthority) existingPending(id string) (count int64) {
	ssa.db.QueryRow("SELECT count(*) FROM pending_authz WHERE id = ?", id).Scan(count)
	return
}

func (ssa *SQLStorageAuthority) existingFinal(id string) (count int64) {
	ssa.db.QueryRow("SELECT count(*) FROM authz WHERE id = ?", id).Scan(count)
	return
}

func (ssa *SQLStorageAuthority) GetAuthorization(id string) (authz Authorization, err error) {
	var jsonAuthz []byte
	if statusIsPending(authz.Status) {
		err = ssa.db.QueryRow("SELECT value FROM pending_authz WHERE id = ?", id).Scan(&jsonAuthz)
	} else {
		err = ssa.db.QueryRow("SELECT value FROM authz WHERE id = ?", id).Scan(&jsonAuthz)
	}
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonAuthz, &authz)
	return
}

func (ssa *SQLStorageAuthority) AddCertificate(cert []byte) (id string, err error) {
	// Manually set the index, to avoid AUTOINCREMENT issues
	var sequence int64
	var scanTarget sql.NullInt64
	err = ssa.db.QueryRow("SELECT max(sequence) FROM certificates").Scan(&scanTarget)
	switch {
	case !scanTarget.Valid:
		sequence = 0
	case err != nil:
		return
	default:
		sequence += scanTarget.Int64 + 1
	}

	id = fingerprint256(cert)
	query := "INSERT INTO certificates (sequence, digest, value) VALUES (?,?,?);"
	_, err = ssa.db.Exec(query, sequence, id, cert)
	return
}

func (ssa *SQLStorageAuthority) NewPendingAuthorization() (id string, err error) {
	// Check that it doesn't exist already
	candidate := newToken()
	for ssa.existingPending(candidate) > 0 || ssa.existingFinal(candidate) > 0 {
		candidate = newToken()
	}

	// Insert a stub row in pending
	_, err = ssa.db.Exec("INSERT INTO pending_authz (id) VALUES (?)", candidate)
	if err != nil {
		return
	}
	id = candidate
	return
}

func (ssa *SQLStorageAuthority) UpdatePendingAuthorization(authz Authorization) (err error) {
	if !statusIsPending(authz.Status) {
		err = errors.New("Use Finalize() to update to a final status")
		return
	}

	if ssa.existingFinal(authz.ID) > 0 {
		err = errors.New("Cannot update a final authorization")
		return
	}

	if ssa.existingPending(authz.ID) != 1 {
		err = errors.New("Requested authorization not found")
		return
	}

	jsonAuthz, err := json.Marshal(authz)
	if err != nil {
		return
	}
	_, err = ssa.db.Exec("UPDATE pending_authz SET value = ? WHERE id = ?", jsonAuthz, authz.ID)
	return
}

func (ssa *SQLStorageAuthority) FinalizeAuthorization(authz Authorization) (err error) {
	// Check that a pending authz exists
	if ssa.existingPending(authz.ID) != 1 {
		err = errors.New("Cannot finalize a authorization that is not pending")
		return
	}
	if !statusIsPending(authz.Status) {
		err = errors.New("Cannot finalize to a non-final status")
		return
	}

	// Manually set the index, to avoid AUTOINCREMENT issues
	var sequence int64
	var scanTarget sql.NullInt64
	err = ssa.db.QueryRow("SELECT max(sequence) FROM authz").Scan(&scanTarget)
	switch {
	case !scanTarget.Valid:
		sequence = 0
	case err != nil:
		return
	default:
		sequence += scanTarget.Int64 + 1
	}

	jsonAuthz, err := json.Marshal(authz)
	if err != nil {
		return
	}
	digest := fingerprint256(jsonAuthz)

	// Add to final table and delete from pending
	tx, err := ssa.db.Begin()
	if err != nil {
		return
	}
	_, err = tx.Exec("INSERT INTO authz (sequence, id, digest, value) VALUES (?, ?, ?, ?)", sequence, authz.ID, digest, jsonAuthz)
	if err != nil {
		tx.Rollback()
		return
	}
	_, err = tx.Exec("DELETE FROM pending_authz WHERE id = ?", authz.ID)
	if err != nil {
		tx.Rollback()
		return
	}
	tx.Commit()
	return
}
