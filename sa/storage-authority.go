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

	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/jose"
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

// Models
type Registration struct {
	Thumbprint        string `db:"thumbprint"`
	core.Registration

	LockCol int64
}

type Pending_auth struct {
	core.Authorization

	LockCol int64
}

type Auth struct {
	Sequence           int64 `db:"sequence"`
	Digest             string `db:"digest"`
	core.Authorization
}

type Certificate struct {
	Serial   string `db:"serial"`
	Digest   string `db:"digest"`
	Content  []byte `db:"content"`
	Issued   time.Time `db:"issued"`
}

type CertificateStatus struct {
	Serial                 string `db:"serial"`
	RevokedDate            time.Time `db:"revokedDate"`
	RevokedReason          int `db:"revokedReason"`
	core.CertificateStatus

	LockCol int64
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
	case core.AcmeIdentifier, jose.JsonWebKey, []core.Challenge, []core.AcmeURL, [][]int:
		jsonBytes, err := json.Marshal(t)
		if err != nil {
			return nil, err
		}
		return string(jsonBytes), nil
	case core.AcmeStatus:
		return string(t), nil
	case core.OCSPStatus:
		return string(t), nil
	default:
		return val, nil
	}
}

func (tc boulderTypeConverter) FromDb(target interface{}) (gorp.CustomScanner, bool) {
	switch target.(type) {
	case *core.AcmeIdentifier, *jose.JsonWebKey, *[]core.Challenge, *[]core.AcmeURL, *[][]int:
		binder := func(holder, target interface{}) error {
			s, ok := holder.(*string)
			if !ok {
				return errors.New("FromDb: Unable to convert *string")
			}
			b := []byte(*s)
			return json.Unmarshal(b, target)
		}
		return gorp.CustomScanner{Holder: new(string), Target: target, Binder: binder}, true
	case *core.AcmeStatus:
		binder := func(holder, target interface{}) error {
			s := holder.(*string)
			st := target.(*core.AcmeStatus)
			*st = core.AcmeStatus(*s)
			return nil
		}
		return gorp.CustomScanner{Holder: new(string), Target: target, Binder: binder}, true
	case *core.OCSPStatus:
		binder := func(holder, target interface{}) error {
			s := holder.(*string)
			st := target.(*core.OCSPStatus)
			*st = core.OCSPStatus(*s)
			return nil
		}
		return gorp.CustomScanner{Holder: new(string), Target: target, Binder: binder}, true
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
	ssa.dbMap.AddTableWithName(Registration{}, "registrations").SetKeys(false, "ID").SetVersionCol("LockCol")
	ssa.dbMap.AddTableWithName(Pending_auth{}, "pending_authz").SetKeys(false, "ID").SetVersionCol("LockCol")
	ssa.dbMap.AddTableWithName(Auth{}, "authz").SetKeys(false, "ID")
	ssa.dbMap.AddTableWithName(Certificate{}, "certificates").SetKeys(false, "Serial")
	ssa.dbMap.AddTableWithName(CertificateStatus{}, "certificateStatus").SetKeys(false, "Serial").SetVersionCol("LockCol")
	ssa.dbMap.AddTableWithName(OcspResponse{}, "ocspResponses").SetKeys(true, "ID")
	ssa.dbMap.AddTableWithName(Crl{}, "crls").SetKeys(false, "Serial")

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
	var certificateStatuses []CertificateStatus
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

func (ssa *SQLStorageAuthority) existingPending(id string) (bool) {
	var count int64
	_ = ssa.dbMap.SelectOne(&count, "SELECT count(*) FROM pending_authz WHERE id = :id", map[string]interface{} {"id": id})
	return count > 0
}

func (ssa *SQLStorageAuthority) existingFinal(id string) (bool) {
	var count int64
	_ = ssa.dbMap.SelectOne(&count, "SELECT count(*) FROM authz WHERE id = :id", map[string]interface{} {"id": id})
	return count > 0
}

func (ssa *SQLStorageAuthority) existingRegistration(id string) (bool) {
	var count int64
	_ = ssa.dbMap.SelectOne(&count, "SELECT count(*) FROM registrations WHERE id = :id", map[string]interface{} {"id": id})
	return count > 0
}

func (ssa *SQLStorageAuthority) GetRegistration(id string) (reg core.Registration, err error) {
	regObj, err := ssa.dbMap.Get(Registration{}, id)
	if err != nil {
		return
	}
	if regObj == nil {
		err = fmt.Errorf("No registrations with ID %s", id)
		return
	}
	regD := regObj.(*Registration)
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
			err = fmt.Errorf("No pending_authz or authz with ID %s", id)
			return
		}
		authD := authObj.(*Auth)
		authz = authD.Authorization
		return
	}
	authD := authObj.(*Pending_auth)
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
	err = ssa.dbMap.SelectOne(&certificate, "SELECT content FROM certificates WHERE serial LIKE :shortSerial",
		map[string]interface{} {"shortSerial": shortSerial+"%"})
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
	err = ssa.dbMap.SelectOne(&certificate, "SELECT content FROM certificates WHERE serial = :serial",
		map[string]interface{} {"serial": serial})
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

	certificateStats, err := ssa.dbMap.Get(CertificateStatus{}, serial)
	if err != nil {
		return
	}

	cs := certificateStats.(*CertificateStatus)
	status = cs.CertificateStatus
	return
}

func (ssa *SQLStorageAuthority) NewRegistration() (id string, err error) {
	// Check that it doesn't exist already
	id = core.NewToken()
	for ssa.existingRegistration(id) {
		id = core.NewToken()
	}

	reg := &Registration{}
	reg.ID = id

	err = ssa.dbMap.Insert(reg)
	if err != nil {
		return
	}

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

	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return
	}

	// TODO: Also update crls.
	ocspResp := &OcspResponse{Serial: serial, CreatedAt: time.Now(), Response: ocspResponse}
	err = tx.Insert(ocspResp)
	if err != nil {
		tx.Rollback()
		return
	}

	statusObj, err := tx.Get(CertificateStatus{}, serial)
	if err != nil {
		tx.Rollback()
		return
	}
	if statusObj == nil {
		err = fmt.Errorf("No certificate with serial %s", serial)
		tx.Rollback()
		return
	}
	status := statusObj.(*CertificateStatus)
	status.Status = core.OCSPStatusRevoked
	status.RevokedDate = time.Now()
	status.RevokedReason = reasonCode

	_, err = tx.Update(status)
	if err != nil {
		tx.Rollback()
		return
	}

	tx.Commit()
	return
}

func (ssa *SQLStorageAuthority) UpdateRegistration(reg core.Registration) (err error) {

	if !ssa.existingRegistration(reg.ID) {
		err = errors.New("Requested registration not found " + reg.ID)
		return
	}

	regObj, err := ssa.dbMap.Get(Registration{}, reg.ID)
	if err != nil {
		return
	}
	newReg := regObj.(*Registration)
	newReg.Registration = reg
	_, err = ssa.dbMap.Update(newReg)
	return
}

func (ssa *SQLStorageAuthority) NewPendingAuthorization() (id string, err error) {
	// Check that it doesn't exist already
	id = core.NewToken()
	for ssa.existingPending(id) || ssa.existingFinal(id) {
		id = core.NewToken()
	}

	// Insert a stub row in pending
	pending_authz := &Pending_auth{Authorization: core.Authorization{ID: id}}
	err = ssa.dbMap.Insert(pending_authz)
	return
}

func (ssa *SQLStorageAuthority) UpdatePendingAuthorization(authz core.Authorization) (err error) {
	if !statusIsPending(authz.Status) {
		err = errors.New("Use Finalize() to update to a final status")
		return
	}

	if ssa.existingFinal(authz.ID) {
		err = errors.New("Cannot update a final authorization")
		return
	}

	if !ssa.existingPending(authz.ID) {
		err = errors.New("Requested authorization not found " + authz.ID)
		return
	}

	authObj, err := ssa.dbMap.Get(Pending_auth{}, authz.ID)
	if err != nil {
		return
	}
	auth := authObj.(*Pending_auth)
	auth.Authorization = authz
	_, err = ssa.dbMap.Update(auth)
	return
}

func (ssa *SQLStorageAuthority) FinalizeAuthorization(authz core.Authorization) (err error) {
	// Check that a pending authz exists
	if !ssa.existingPending(authz.ID) {
		err = errors.New("Cannot finalize a authorization that is not pending")
		return
	}
	if statusIsPending(authz.Status) {
		err = errors.New("Cannot finalize to a non-final status")
		return
	}

	// Manually set the index, to avoid AUTOINCREMENT issues
	var sequence int64
	sequenceObj, err := ssa.dbMap.SelectNullInt("SELECT max(sequence) FROM authz")
	switch {
	case !sequenceObj.Valid:
		sequence = 0
	case err != nil:
		return
	default:
		sequence += sequenceObj.Int64 + 1
	}

	jsonAuthz, err := json.Marshal(authz)
	if err != nil {
		return
	}
	// ???: is this still needed? ^+v
	digest := core.Fingerprint256(jsonAuthz)

	auth := &Auth{sequence, digest, authz}
	authObj, err := ssa.dbMap.Get(Pending_auth{}, authz.ID)
	if err != nil {
		return
	}
	oldAuth := authObj.(*Pending_auth)

	err = ssa.dbMap.Insert(auth)
	if err != nil {
		return
	}

	_, err = ssa.dbMap.Delete(oldAuth)
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
	certStatus := &CertificateStatus{serial, time.Time{}, 0,
		core.CertificateStatus{SubscriberApproved: false, Status: core.OCSPStatus("good"), OCSPLastUpdated: time.Time{}}, 0}
	
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
