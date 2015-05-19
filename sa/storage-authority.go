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
	"sort"
	"strings"
	"time"

	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"

	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

type SQLStorageAuthority struct {
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
	"mysql":    gorp.MySQLDialect{Engine: "InnoDB", Encoding: "UTF8"},
	"postgres": gorp.PostgresDialect{},
}

// Utility models
type pendingauthzModel struct {
	core.Authorization

	LockCol int64
}

type authzModel struct {
	core.Authorization

	Sequence int64 `db:"sequence"`
}

func NewDbMap(driver, dbName string) (dbMap *gorp.DbMap, err error) {
	db, err := sql.Open(driver, dbName)
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

	dbMap = &gorp.DbMap{Db: db, Dialect: dialect, TypeConverter: BoulderTypeConverter{}}
	return
}

// SQLLogger adapts the AuditLogger to a format GORP can use.
type SQLLogger struct {
	log *blog.AuditLogger
}

// Printf adapts the AuditLogger to GORP's interface
func (log *SQLLogger) Printf(format string, v ...interface{}) {
	log.log.Debug(fmt.Sprintf(format, v))
}

// NewSQLStorageAuthority provides persistence using a SQL backend for Boulder.
func NewSQLStorageAuthority(driver string, name string) (ssa *SQLStorageAuthority, err error) {
	logger := blog.GetAuditLogger()
	logger.Notice("Storage Authority Starting")

	dbMap, err := NewDbMap(driver, name)
	if err != nil {
		return
	}

	ssa = &SQLStorageAuthority{
		dbMap:  dbMap,
		log:    logger,
		bucket: make(map[string]interface{}),
	}

	ssa.initTables()
	return
}

// SetSQLDebug enables/disables GORP SQL-level Debugging
func (ssa *SQLStorageAuthority) SetSQLDebug(state bool) {
	ssa.dbMap.TraceOff()

	if state {
		// Enable logging
		ssa.dbMap.TraceOn("SQL: ", &SQLLogger{blog.GetAuditLogger()})
	}
}

// initTables constructs the table map for the ORM. If you want to also create
// the tables, call CreateTablesIfNotExists.
func (ssa *SQLStorageAuthority) initTables() {
	regTable := ssa.dbMap.AddTableWithName(core.Registration{}, "registrations").SetKeys(true, "ID")
	regTable.SetVersionCol("LockCol")
	regTable.ColMap("Key").SetMaxSize(1024).SetNotNull(true)

	pendingAuthzTable := ssa.dbMap.AddTableWithName(pendingauthzModel{}, "pending_authz").SetKeys(false, "ID")
	pendingAuthzTable.SetVersionCol("LockCol")
	pendingAuthzTable.ColMap("Challenges").SetMaxSize(1536)

	authzTable := ssa.dbMap.AddTableWithName(authzModel{}, "authz").SetKeys(false, "ID")
	authzTable.ColMap("Challenges").SetMaxSize(1536)

	ssa.dbMap.AddTableWithName(core.Certificate{}, "certificates").SetKeys(false, "Serial")
	ssa.dbMap.AddTableWithName(core.CertificateStatus{}, "certificateStatus").SetKeys(false, "Serial").SetVersionCol("LockCol")
	ssa.dbMap.AddTableWithName(core.OcspResponse{}, "ocspResponses").SetKeys(true, "ID")
	ssa.dbMap.AddTableWithName(core.Crl{}, "crls").SetKeys(false, "Serial")
	ssa.dbMap.AddTableWithName(core.DeniedCsr{}, "deniedCsrs").SetKeys(true, "ID")
}

// CreateTablesIfNotExists instructs the ORM to create any missing tables.
func (ssa *SQLStorageAuthority) CreateTablesIfNotExists() (err error) {
	err = ssa.dbMap.CreateTablesIfNotExists()
	return
}

func (ssa *SQLStorageAuthority) DumpTables() error {
	tx, err := ssa.dbMap.Begin()
	if err != nil {
		tx.Rollback()
		return err
	}

	fmt.Printf("===== TABLE DUMP =====\n")

	fmt.Printf("\n----- registrations -----\n")
	var registrations []core.Registration
	_, err = tx.Select(&registrations, "SELECT * FROM registrations")
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, r := range registrations {
		fmt.Printf("%+v\n", r)
	}

	fmt.Printf("\n----- pending_authz -----\n")
	var pending_authz []pendingauthzModel
	_, err = tx.Select(&pending_authz, "SELECT * FROM pending_authz")
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, pa := range pending_authz {
		fmt.Printf("%+v\n", pa)
	}

	fmt.Printf("\n----- authz -----\n")
	var authz []authzModel
	_, err = tx.Select(&authz, "SELECT * FROM authz")
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, a := range authz {
		fmt.Printf("%+v\n", a)
	}

	fmt.Printf("\n----- certificates -----\n")
	var certificates []core.Certificate
	_, err = tx.Select(&certificates, "SELECT * FROM certificates")
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, c := range certificates {
		fmt.Printf("%+v\n", c)
	}

	fmt.Printf("\n----- certificateStatus -----\n")
	var certificateStatuses []core.CertificateStatus
	_, err = tx.Select(&certificateStatuses, "SELECT * FROM certificateStatus")
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, cS := range certificateStatuses {
		fmt.Printf("%+v\n", cS)
	}

	fmt.Printf("\n----- ocspResponses -----\n")
	var ocspResponses []core.OcspResponse
	_, err = tx.Select(&ocspResponses, "SELECT * FROM ocspResponses")
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, oR := range ocspResponses {
		fmt.Printf("%+v\n", oR)
	}

	fmt.Printf("\n----- crls -----\n")
	var crls []core.Crl
	_, err = tx.Select(&crls, "SELECT * FROM crls")
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, c := range crls {
		fmt.Printf("%+v\n", c)
	}

	fmt.Printf("\n----- deniedCsrs -----\n")
	var dCsrs []core.DeniedCsr
	_, err = tx.Select(&dCsrs, "SELECT * FROM deniedCsrs")
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, c := range dCsrs {
		fmt.Printf("%+v\n", c)
	}

	err = tx.Commit()
	return err
}

func statusIsPending(status core.AcmeStatus) bool {
	return status == core.StatusPending || status == core.StatusProcessing || status == core.StatusUnknown
}

func existingPending(tx *gorp.Transaction, id string) bool {
	var count int64
	_ = tx.SelectOne(&count, "SELECT count(*) FROM pending_authz WHERE id = :id", map[string]interface{}{"id": id})
	return count > 0
}

func existingFinal(tx *gorp.Transaction, id string) bool {
	var count int64
	_ = tx.SelectOne(&count, "SELECT count(*) FROM authz WHERE id = :id", map[string]interface{}{"id": id})
	return count > 0
}

func existingRegistration(tx *gorp.Transaction, id int64) bool {
	var count int64
	_ = tx.SelectOne(&count, "SELECT count(*) FROM registrations WHERE id = :id", map[string]interface{}{"id": id})
	return count > 0
}

func (ssa *SQLStorageAuthority) GetRegistration(id int64) (reg core.Registration, err error) {
	regObj, err := ssa.dbMap.Get(core.Registration{}, id)
	if err != nil {
		return
	}
	if regObj == nil {
		err = fmt.Errorf("No registrations with ID %d", id)
		return
	}
	reg = *regObj.(*core.Registration)
	return
}

func (ssa *SQLStorageAuthority) GetRegistrationByKey(key jose.JsonWebKey) (reg core.Registration, err error) {
	keyJson, err := json.Marshal(key)
	if err != nil {
		return
	}

	err = ssa.dbMap.SelectOne(&reg, "SELECT * FROM registrations WHERE jwk = :key", map[string]interface{}{"key": string(keyJson)})
	return
}

func (ssa *SQLStorageAuthority) GetAuthorization(id string) (authz core.Authorization, err error) {
	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return
	}

	authObj, err := tx.Get(pendingauthzModel{}, id)
	if err != nil {
		tx.Rollback()
		return
	}
	if authObj == nil {
		authObj, err = tx.Get(authzModel{}, id)
		if err != nil {
			tx.Rollback()
			return
		}
		if authObj == nil {
			err = fmt.Errorf("No pending_authz or authz with ID %s", id)
			tx.Rollback()
			return
		}
		authD := authObj.(*authzModel)
		authz = authD.Authorization

		err = tx.Commit()
		return
	}
	authD := *authObj.(*pendingauthzModel)
	authz = authD.Authorization

	err = tx.Commit()
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

	var certificate core.Certificate
	err = ssa.dbMap.SelectOne(&certificate, "SELECT * FROM certificates WHERE serial LIKE :shortSerial",
		map[string]interface{}{"shortSerial": shortSerial + "%"})
	if err != nil {
		return
	}
	return certificate.DER, nil
}

// GetCertificate takes a serial number and returns the corresponding
// certificate, or error if it does not exist.
func (ssa *SQLStorageAuthority) GetCertificate(serial string) (cert []byte, err error) {
	if len(serial) != 32 {
		err = errors.New("Invalid certificate serial " + serial)
		return
	}

	var certificate core.Certificate
	err = ssa.dbMap.SelectOne(&certificate, "SELECT * FROM certificates WHERE serial = :serial",
		map[string]interface{}{"serial": serial})
	if err != nil {
		return
	}
	return certificate.DER, nil
}

// GetCertificateStatus takes a hexadecimal string representing the full 128-bit serial
// number of a certificate and returns data about that certificate's current
// validity.
func (ssa *SQLStorageAuthority) GetCertificateStatus(serial string) (status core.CertificateStatus, err error) {
	if len(serial) != 32 {
		err = errors.New("Invalid certificate serial " + serial)
		return
	}

	certificateStats, err := ssa.dbMap.Get(core.CertificateStatus{}, serial)
	if err != nil {
		return
	}

	status = *certificateStats.(*core.CertificateStatus)
	return
}

func (ssa *SQLStorageAuthority) NewRegistration(reg core.Registration) (output core.Registration, err error) {
	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return
	}

	err = tx.Insert(&reg)
	if err != nil {
		tx.Rollback()
		return
	}

	err = tx.Commit()
	return reg, err
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

	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return
	}

	// TODO: Also update crls.
	ocspResp := &core.OcspResponse{Serial: serial, CreatedAt: time.Now(), Response: ocspResponse}
	err = tx.Insert(ocspResp)
	if err != nil {
		tx.Rollback()
		return
	}

	statusObj, err := tx.Get(core.CertificateStatus{}, serial)
	if err != nil {
		tx.Rollback()
		return
	}
	if statusObj == nil {
		err = fmt.Errorf("No certificate with serial %s", serial)
		tx.Rollback()
		return
	}
	status := statusObj.(*core.CertificateStatus)
	status.Status = core.OCSPStatusRevoked
	status.RevokedDate = time.Now()
	status.RevokedReason = reasonCode

	_, err = tx.Update(status)
	if err != nil {
		tx.Rollback()
		return
	}

	err = tx.Commit()
	return
}

func (ssa *SQLStorageAuthority) UpdateRegistration(reg core.Registration) (err error) {
	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return
	}

	if !existingRegistration(tx, reg.ID) {
		err = fmt.Errorf("Requested registration not found %v", reg.ID)
		tx.Rollback()
		return
	}

	_, err = tx.Update(&reg)
	if err != nil {
		tx.Rollback()
		return
	}

	err = tx.Commit()
	return
}

func (ssa *SQLStorageAuthority) NewPendingAuthorization() (id string, err error) {
	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return
	}

	// Check that it doesn't exist already
	id = core.NewToken()
	for existingPending(tx, id) || existingFinal(tx, id) {
		id = core.NewToken()
	}

	// Insert a stub row in pending
	pending_authz := &pendingauthzModel{Authorization: core.Authorization{ID: id}}
	err = tx.Insert(pending_authz)
	if err != nil {
		tx.Rollback()
		return
	}

	err = tx.Commit()
	return
}

func (ssa *SQLStorageAuthority) UpdatePendingAuthorization(authz core.Authorization) (err error) {
	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return
	}

	if !statusIsPending(authz.Status) {
		err = errors.New("Use FinalizeAuthorization() to update to a final status")
		tx.Rollback()
		return
	}

	if existingFinal(tx, authz.ID) {
		err = errors.New("Cannot update a final authorization")
		tx.Rollback()
		return
	}

	if !existingPending(tx, authz.ID) {
		err = errors.New("Requested authorization not found " + authz.ID)
		tx.Rollback()
		return
	}

	authObj, err := tx.Get(pendingauthzModel{}, authz.ID)
	if err != nil {
		tx.Rollback()
		return
	}
	auth := authObj.(*pendingauthzModel)
	auth.Authorization = authz
	_, err = tx.Update(auth)
	if err != nil {
		tx.Rollback()
		return
	}

	err = tx.Commit()
	return
}

func (ssa *SQLStorageAuthority) FinalizeAuthorization(authz core.Authorization) (err error) {
	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return
	}

	// Check that a pending authz exists
	if !existingPending(tx, authz.ID) {
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
	sequenceObj, err := tx.SelectNullInt("SELECT max(sequence) FROM authz")
	switch {
	case !sequenceObj.Valid:
		sequence = 0
	case err != nil:
		return
	default:
		sequence += sequenceObj.Int64 + 1
	}

	auth := &authzModel{authz, sequence}
	authObj, err := tx.Get(pendingauthzModel{}, authz.ID)
	if err != nil {
		tx.Rollback()
		return
	}
	oldAuth := authObj.(*pendingauthzModel)

	err = tx.Insert(auth)
	if err != nil {
		tx.Rollback()
		return
	}

	_, err = tx.Delete(oldAuth)
	if err != nil {
		tx.Rollback()
		return
	}

	err = tx.Commit()
	return
}

func (ssa *SQLStorageAuthority) AddCertificate(certDER []byte, regID int64) (digest string, err error) {
	var parsedCertificate *x509.Certificate
	parsedCertificate, err = x509.ParseCertificate(certDER)
	if err != nil {
		return
	}
	digest = core.Fingerprint256(certDER)
	serial := core.SerialToString(parsedCertificate.SerialNumber)

	cert := &core.Certificate{
		RegistrationID: regID,
		Serial:         serial,
		Digest:         digest,
		DER:            certDER,
		Issued:         time.Now(),
	}
	certStatus := &core.CertificateStatus{
		SubscriberApproved: false,
		Status:             core.OCSPStatus("good"),
		OCSPLastUpdated:    time.Time{},
		Serial:             serial,
		RevokedDate:        time.Time{},
		RevokedReason:      0,
		LockCol:            0,
	}

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

func (ssa *SQLStorageAuthority) AlreadyDeniedCSR(names []string) (already bool, err error) {
	sort.Strings(names)

	var denied int64
	err = ssa.dbMap.SelectOne(
		&denied,
		"SELECT count(*) FROM deniedCsrs WHERE names = :names",
		map[string]interface{}{"names": strings.ToLower(strings.Join(names, ","))},
	)
	if err != nil {
		return
	}
	if denied > 0 {
		already = true
	}

	return
}
