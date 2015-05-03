// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sa

import (
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

type SQLStorageAuthority struct {
	db     *sql.DB
	dbMap  *gorp.DbMap
	bucket map[string]interface{} // XXX included only for backward compat
	log    *blog.AuditLogger
}

func digest256(data []byte) []byte {
	d := sha256.New()
	_, _ = d.Write(data) // Never returns an error
	return d.Sum(nil)
}

var dialectMap map[string]interface{} = map[string]interface{}{
	"sqlite3":  gorp.SqliteDialect{},
	"mysql":    gorp.MySQLDialect{"InnoDB", "UTF8"},
	"postgres": gorp.PostgresDialect{},
}

// Models
type Registration struct {
	Thumbprint        string `db:"thumbprint"`
	core.Registration
}

type Pending_auth struct {
	core.Authorization
}

type Auth struct {
	Sequence           string `db:"sequence"`
	Digest             string `db:"digest"`
	core.Authorization
}

type Certificate struct {
	Serial   string `db:"serial"`
	Digest   string `db:"digest"`
	Content  []byte `db:"content"`
	Issued   time.Time `db:"issued"`
}

type CertificateStats struct {
	Serial                 string `db:"serial"`
	RevokedDate            time.Time `db:"revokedDate"`
	RevokedReason          int `db:"revokedReason"`
	core.CertificateStatus
}

type OcspResponse struct {
	ID        int `db:"id"`
	Serial    string `db:"serial"`
	CreatedAt time.Time `db:"createdAt"`
	Response  []byte `db:"response"`
}

type Crl struct {
	Serial    string `db:"serial"`
	CreatedAt time.Time `db:"createdAt"`
	Crl       string `db:"crl"`
}

// Type converter
type boulderTypeConverter struct{}

func (tc boulderTypeConverter) ToDb(val interface{}) (interface{}, error) {
	switch t := val.(type) {
	case core.OCSPStatus:
		return string(t), nil
	default:
		return val, nil
	}
}

func (tc boulderTypeConverter) FromDb(target interface{}) (gorp.CustomScanner, bool) {
	switch target.(type) {
	case *core.OCSPStatus:
		binder := func(holder, target interface{}) error {
			s, ok := holder.(*string)
			if !ok {
				return errors.New("FromDb: Unable to convert core.OCSPStatus to string")
			}
			st, ok := target.(*core.OCSPStatus)
			if !ok {
				return errors.New("FromDb: Unable to convert core.OCSPStatus to string")
			}
			*st = core.OCSPStatus(string(*s))
			return nil
		}
		return gorp.CustomScanner{new(string), target, binder}, true
	default:
		return gorp.CustomScanner{}, false
	}
}

func NewSQLStorageAuthority(driver string, name string) (ssa *SQLStorageAuthority, err error) {
	logger := blog.GetAuditLogger()
	logger.Notice("Storage Authority Starting")

	db, err := sql.Open(driver, name)
	if err != nil {
		return
	}
	if err = db.Ping(); err != nil {
		return
	}

	dialect, ok := dialectMap[driver].(gorp.Dialect)
	if !ok {
		err = fmt.Errorf("Couldn't find dialect for %s", driver)
		return
	}

	dbmap := &gorp.DbMap{Db: db, Dialect: dialect, TypeConverter: boulderTypeConverter{}}

	ssa = &SQLStorageAuthority{
		db:     db,
		dbMap:  dbmap,
		log:    logger,
		bucket: make(map[string]interface{}),
	}

	err = ssa.InitTables()
	if err != nil {
		return
	}

	return
}

func (ssa *SQLStorageAuthority) InitTables() (err error) {
	ssa.dbMap.AddTableWithName(Registration{}, "registrations").SetKeys(false, "ID")
	ssa.dbMap.AddTableWithName(Pending_auth{}, "pending_authz").SetKeys(false, "ID")
	ssa.dbMap.AddTableWithName(Auth{}, "authz").SetKeys(false, "ID")
	ssa.dbMap.AddTableWithName(Certificate{}, "certificates").SetKeys(false, "Serial")
	ssa.dbMap.AddTableWithName(CertificateStats{}, "certificateStatus").SetKeys(false, "Serial")
	ssa.dbMap.AddTableWithName(OcspResponse{}, "ocspResponses").SetKeys(true, "ID")
	ssa.dbMap.AddTableWithName(Crl{}, "crls").SetKeys(false, "CreatedAt")

	err = ssa.dbMap.CreateTablesIfNotExists()
	return
}

func (ssa *SQLStorageAuthority) DumpTables() {
	fmt.Printf("===== TABLE DUMP =====\n")

	fmt.Printf("\n----- registrations -----\n")
	var registrations []Registration
	_, err := ssa.dbMap.Select(&registrations, "SELECT * FROM registrations ")
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, r := range registrations {
		fmt.Printf("%+v\n", r)
	}

	fmt.Printf("\n----- pending_authz -----\n")
	var pending_authz []Pending_auth
	_, err = ssa.dbMap.Select(&pending_authz, "SELECT * FROM pending_authz")
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, pa := range pending_authz {
		fmt.Printf("%+v\n", pa)
	}

	fmt.Printf("\n----- authz -----\n")
	var authz []Auth
	_, err = ssa.dbMap.Select(&authz, "SELECT * FROM authz")
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, a := range authz {
		fmt.Printf("%+v\n", a)
	}

	fmt.Printf("\n----- certificates -----\n")
	var certificates []Certificate
	_, err = ssa.dbMap.Select(&certificates, "SELECT * FROM certificates")
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, c := range certificates {
		fmt.Printf("%+v\n", c)
	}

	fmt.Printf("\n----- certificateStatus -----\n")
	var certificateStatuses []CertificateStats
	_, err = ssa.dbMap.Select(&certificateStatuses, "SELECT * FROM certificateStatus")
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, cS := range certificateStatuses {
		fmt.Printf("%+v\n", cS)
	}

	fmt.Printf("\n----- ocspResponses -----\n")
	var ocspResponses []OcspResponse
	_, err = ssa.dbMap.Select(&ocspResponses, "SELECT * FROM ocspResponses")
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, oR := range ocspResponses {
		fmt.Printf("%+v\n", oR)
	}

	fmt.Printf("\n----- crls -----\n")
	var crls []Crl
	_, err = ssa.dbMap.Select(&crls, "SELECT * FROM crls")
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, c := range crls {
		fmt.Printf("%+v\n", c)
	}
}

func statusIsPending(status core.AcmeStatus) bool {
	return status == core.StatusPending || status == core.StatusProcessing || status == core.StatusUnknown
}

func existingPending(tx *sql.Tx, id string) (count int64) {
	tx.QueryRow("SELECT count(*) FROM pending_authz WHERE id = ?;", id).Scan(&count)
	return
}

func existingFinal(tx *sql.Tx, id string) (count int64) {
	tx.QueryRow("SELECT count(*) FROM authz WHERE id = ?;", id).Scan(&count)
	return
}

func existingRegistration(tx *sql.Tx, id string) (count int64) {
	tx.QueryRow("SELECT count(*) FROM registrations WHERE id = ?;", id).Scan(&count)
	return
}

func (ssa *SQLStorageAuthority) GetRegistration(id string) (reg core.Registration, err error) {
	regObj, err := ssa.dbMap.Get(Registration{}, id)
	if err != nil {
		return
	}
	regD, ok := regObj.(Registration)
	if !ok {
		err = fmt.Errorf("Couldn't convert interface{} to Registration")
		return
	}
	reg = regD.Registration
	return
}

func (ssa *SQLStorageAuthority) GetAuthorization(id string) (authz core.Authorization, err error) {
	authObj, err := ssa.dbMap.Get(Pending_auth{}, id)
	if err != nil {
		return
	}
	if authObj == nil {
		authObj, err = ssa.dbMap.Get(Auth{}, id)
		if err != nil {
			return
		}
		if authObj == nil {
			err = fmt.Errorf("No pending_authorization or authorization matches ID %s", id)
			return
		}
	}
	authD, ok := authObj.(Auth)
	if !ok {
		err = fmt.Errorf("Couldn't convert interface{} to Authorization")
		return
	}
	authz = authD.Authorization
	return
}

// GetCertificateByShortSerial takes an id consisting of the first, sequential half of a
// serial number and returns the first certificate whose full serial number is
// lexically greater than that id. This allows clients to query on the known
// sequential half of our serial numbers to enumerate all certificates.
// TODO: Implement error when there are multiple certificates with the same
// sequential half.
func (ssa *SQLStorageAuthority) GetCertificateByShortSerial(shortSerial string) (cert []byte, err error) {
	if len(shortSerial) != 16 {
		err = errors.New("Invalid certificate short serial " + shortSerial)
		return
	}

	var certificate Certificate
	err = ssa.dbMap.SelectOne(&certificate, "SELECT content FROM certificates WHERE serial LIKE ?", shortSerial+"%")
	if err != nil {
		return
	}
	cert = certificate.Content
	return
}

// GetCertificate takes a serial number and returns the corresponding
// certificate, or error if it does not exist.
func (ssa *SQLStorageAuthority) GetCertificate(serial string) (cert []byte, err error) {
	if len(serial) != 32 {
		err = errors.New("Invalid certificate serial " + serial)
		return
	}

	var certificate Certificate
	err = ssa.dbMap.SelectOne(&certificate, "SELECT content FROM certificates WHERE serial = ?", serial)
	if err != nil {
		return
	}
	cert = certificate.Content
	return
}

// GetCertificateStatus takes a hexadecimal string representing the full 128-bit serial
// number of a certificate and returns data about that certificate's current
// validity.
func (ssa *SQLStorageAuthority) GetCertificateStatus(serial string) (status core.CertificateStatus, err error) {
	if len(serial) != 32 {
		err = errors.New("Invalid certificate serial " + serial)
		return
	}

	certificateStats, err := ssa.dbMap.Get(CertificateStats{}, serial)
	if err != nil {
		return
	}

	cs, ok := certificateStats.(*CertificateStats)
	if !ok {
		err = fmt.Errorf("Couldn't convert interface{} to CertificateStats")
		return
	}
	status = cs.CertificateStatus
	return
}

func (ssa *SQLStorageAuthority) NewRegistration() (id string, err error) {
	tx, err := ssa.db.Begin()
	if err != nil {
		return
	}

	// Check that it doesn't exist already
	candidate := core.NewToken()
	for existingRegistration(tx, candidate) > 0 {
		candidate = core.NewToken()
	}

	// Insert a stub row in pending
	_, err = tx.Exec("INSERT INTO registrations (id) VALUES (?);", candidate)
	if err != nil {
		tx.Rollback()
		return
	}

	if err = tx.Commit(); err != nil {
		return
	}

	id = candidate
	return
}

// MarkCertificateRevoked stores the fact that a certificate is revoked, along
// with a timestamp and a reason.
func (ssa *SQLStorageAuthority) MarkCertificateRevoked(serial string, ocspResponse []byte, reasonCode int) (err error) {
	if _, err = ssa.GetCertificate(serial); err != nil {
		return errors.New(fmt.Sprintf(
			"Unable to mark certificate %s revoked: cert not found.", serial))
	}

	if _, err = ssa.GetCertificateStatus(serial); err != nil {
		return errors.New(fmt.Sprintf(
			"Unable to mark certificate %s revoked: cert status not found.", serial))
	}

	tx, err := ssa.db.Begin()
	if err != nil {
		return
	}

	// TODO: Also update crls.
	_, err = tx.Exec(`INSERT INTO ocspResponses (serial, createdAt, response)
			values (?, ?, ?)`,
		serial, time.Now(), ocspResponse)
	if err != nil {
		tx.Rollback()
		return
	}

	_, err = tx.Exec(`UPDATE certificateStatus SET
		status=?, revokedDate=?, revokedReason=? WHERE serial=?`,
		string(core.OCSPStatusRevoked), time.Now(), reasonCode, serial)
	if err != nil {
		tx.Rollback()
		return
	}
	err = tx.Commit()
	return
}

func (ssa *SQLStorageAuthority) UpdateRegistration(reg core.Registration) (err error) {
	tx, err := ssa.db.Begin()
	if err != nil {
		return
	}

	if existingRegistration(tx, reg.ID) != 1 {
		err = errors.New("Requested registration not found " + reg.ID)
		tx.Rollback()
		return
	}

	jsonReg, err := json.Marshal(reg)
	if err != nil {
		tx.Rollback()
		return
	}

	_, err = tx.Exec("UPDATE registrations SET thumbprint=?, value=? WHERE id = ?;", reg.Key.Thumbprint, string(jsonReg), reg.ID)
	if err != nil {
		tx.Rollback()
		return
	}

	err = tx.Commit()
	return
}

func (ssa *SQLStorageAuthority) NewPendingAuthorization() (id string, err error) {
	tx, err := ssa.db.Begin()
	if err != nil {
		return
	}

	// Check that it doesn't exist already
	candidate := core.NewToken()
	for existingPending(tx, candidate) > 0 || existingFinal(tx, candidate) > 0 {
		candidate = core.NewToken()
	}

	// Insert a stub row in pending
	_, err = tx.Exec("INSERT INTO pending_authz (id) VALUES (?);", candidate)
	if err != nil {
		tx.Rollback()
		return
	}

	if err = tx.Commit(); err != nil {
		return
	}

	id = candidate
	return
}

func (ssa *SQLStorageAuthority) UpdatePendingAuthorization(authz core.Authorization) (err error) {
	tx, err := ssa.db.Begin()
	if err != nil {
		return
	}

	if !statusIsPending(authz.Status) {
		err = errors.New("Use Finalize() to update to a final status")
		tx.Rollback()
		return
	}

	if existingFinal(tx, authz.ID) > 0 {
		err = errors.New("Cannot update a final authorization")
		tx.Rollback()
		return
	}

	if existingPending(tx, authz.ID) != 1 {
		err = errors.New("Requested authorization not found " + authz.ID)
		tx.Rollback()
		return
	}

	jsonAuthz, err := json.Marshal(authz)
	if err != nil {
		tx.Rollback()
		return
	}

	_, err = tx.Exec("UPDATE pending_authz SET value = ? WHERE id = ?;", jsonAuthz, authz.ID)
	if err != nil {
		tx.Rollback()
		return
	}

	err = tx.Commit()
	return
}

func (ssa *SQLStorageAuthority) FinalizeAuthorization(authz core.Authorization) (err error) {
	tx, err := ssa.db.Begin()
	if err != nil {
		return
	}

	// Check that a pending authz exists
	if existingPending(tx, authz.ID) != 1 {
		err = errors.New("Cannot finalize a authorization that is not pending")
		tx.Rollback()
		return
	}
	if statusIsPending(authz.Status) {
		err = errors.New("Cannot finalize to a non-final status")
		tx.Rollback()
		return
	}

	// Manually set the index, to avoid AUTOINCREMENT issues
	var sequence int64
	var scanTarget sql.NullInt64
	err = tx.QueryRow("SELECT max(sequence) FROM authz").Scan(&scanTarget)
	switch {
	case !scanTarget.Valid:
		sequence = 0
	case err != nil:
		tx.Rollback()
		return
	default:
		sequence += scanTarget.Int64 + 1
	}

	jsonAuthz, err := json.Marshal(authz)
	if err != nil {
		tx.Rollback()
		return
	}
	digest := core.Fingerprint256(jsonAuthz)

	// Add to final table and delete from pending
	if err != nil {
		tx.Rollback()
		return
	}
	_, err = tx.Exec("INSERT INTO authz (sequence, id, digest, value) VALUES (?, ?, ?, ?);", sequence, authz.ID, digest, jsonAuthz)
	if err != nil {
		tx.Rollback()
		return
	}
	_, err = tx.Exec("DELETE FROM pending_authz WHERE id = ?;", authz.ID)
	if err != nil {
		tx.Rollback()
		return
	}
	err = tx.Commit()
	return
}

func (ssa *SQLStorageAuthority) AddCertificate(certDER []byte) (digest string, err error) {
	var parsedCertificate *x509.Certificate
	parsedCertificate, err = x509.ParseCertificate(certDER)
	if err != nil {
		return
	}
	serial := fmt.Sprintf("%032x", parsedCertificate.SerialNumber)
	digest = core.Fingerprint256(certDER)

	cert := &Certificate{serial, digest, certDER, time.Now()}
	certStatus := &CertificateStats{serial, time.Time{}, 0, core.CertificateStatus{false, "good", time.Time{}}}
	
	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return
	}

	err = tx.Insert(cert)
	if err != nil {
		tx.Rollback()
		return
	}

	err = tx.Insert(certStatus)
	if err != nil {
		tx.Rollback()
		return
	}

	err = tx.Commit()
	return
}
