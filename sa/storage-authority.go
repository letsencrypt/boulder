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

	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

const getChallengesQuery = "SELECT * FROM challenges WHERE authorizationID = :authID ORDER BY id ASC"

// SQLStorageAuthority defines a Storage Authority
type SQLStorageAuthority struct {
	dbMap *gorp.DbMap
	log   *blog.AuditLogger
}

func digest256(data []byte) []byte {
	d := sha256.New()
	_, _ = d.Write(data) // Never returns an error
	return d.Sum(nil)
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

// NewSQLStorageAuthority provides persistence using a SQL backend for
// Boulder. It will modify the given gorp.DbMap by adding relevent tables.
func NewSQLStorageAuthority(dbMap *gorp.DbMap) (*SQLStorageAuthority, error) {
	logger := blog.GetAuditLogger()

	logger.Notice("Storage Authority Starting")

	ssa := &SQLStorageAuthority{
		dbMap: dbMap,
		log:   logger,
	}

	return ssa, nil
}

// SetSQLDebug enables/disables GORP SQL-level Debugging
func (ssa *SQLStorageAuthority) SetSQLDebug(state bool) {
	SetSQLDebug(ssa.dbMap, state)
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

func updateChallenges(authID string, challenges []core.Challenge, tx *gorp.Transaction) error {
	var challs []challModel
	_, err := tx.Select(
		&challs,
		getChallengesQuery,
		map[string]interface{}{"authID": authID},
	)
	if err != nil {
		return err
	}
	if len(challs) != len(challenges) {
		return fmt.Errorf("Invalid number of challenges provided")
	}
	for i, authChall := range challenges {
		chall, err := challengeToModel(&authChall, challs[i].AuthorizationID)
		if err != nil {
			return err
		}
		chall.ID = challs[i].ID
		_, err = tx.Update(chall)
		if err != nil {
			return err
		}
	}
	return nil
}

type NoSuchRegistrationError struct {
	Msg string
}

func (e NoSuchRegistrationError) Error() string {
	return e.Msg
}

// GetRegistration obtains a Registration by ID
func (ssa *SQLStorageAuthority) GetRegistration(id int64) (core.Registration, error) {
	regObj, err := ssa.dbMap.Get(regModel{}, id)
	if err != nil {
		return core.Registration{}, err
	}
	if regObj == nil {
		msg := fmt.Sprintf("No registrations with ID %d", id)
		return core.Registration{}, NoSuchRegistrationError{Msg: msg}
	}
	regPtr, ok := regObj.(*regModel)
	if !ok {
		return core.Registration{}, fmt.Errorf("Invalid cast to reg model object")
	}
	return modelToRegistration(regPtr)
}

// GetRegistrationByKey obtains a Registration by JWK
func (ssa *SQLStorageAuthority) GetRegistrationByKey(key jose.JsonWebKey) (core.Registration, error) {
	reg := &regModel{}
	sha, err := core.KeyDigest(key.Key)
	if err != nil {
		return core.Registration{}, err
	}
	err = ssa.dbMap.SelectOne(reg, "SELECT * FROM registrations WHERE jwk_sha256 = :key", map[string]interface{}{"key": sha})

	if err == sql.ErrNoRows {
		msg := fmt.Sprintf("No registrations with public key sha256 %s", sha)
		return core.Registration{}, NoSuchRegistrationError{Msg: msg}
	}
	if err != nil {
		return core.Registration{}, err
	}

	return modelToRegistration(reg)
}

// GetAuthorization obtains an Authorization by ID
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
	if authObj != nil {
		authD := *authObj.(*pendingauthzModel)
		authz = authD.Authorization
	} else {
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
	}

	var challObjs []challModel
	_, err = tx.Select(
		&challObjs,
		getChallengesQuery,
		map[string]interface{}{"authID": authz.ID},
	)
	if err != nil {
		tx.Rollback()
		return
	}
	var challs []core.Challenge
	for _, c := range challObjs {
		chall, err := modelToChallenge(&c)
		if err != nil {
			tx.Rollback()
			return core.Authorization{}, err
		}
		challs = append(challs, chall)
	}
	authz.Challenges = challs

	err = tx.Commit()
	return
}

// GetLatestValidAuthorization gets the valid authorization with biggest expire date for a given domain and registrationId
func (ssa *SQLStorageAuthority) GetLatestValidAuthorization(registrationId int64, identifier core.AcmeIdentifier) (authz core.Authorization, err error) {
	ident, err := json.Marshal(identifier)
	if err != nil {
		return
	}
	var auth core.Authorization
	err = ssa.dbMap.SelectOne(&auth, "SELECT id FROM authz "+
		"WHERE identifier = :identifier AND registrationID = :registrationId AND status = 'valid' "+
		"ORDER BY expires DESC LIMIT 1",
		map[string]interface{}{"identifier": string(ident), "registrationId": registrationId})
	if err != nil {
		return
	}

	return ssa.GetAuthorization(auth.ID)
}

// GetCertificateByShortSerial takes an id consisting of the first, sequential half of a
// serial number and returns the first certificate whose full serial number is
// lexically greater than that id. This allows clients to query on the known
// sequential half of our serial numbers to enumerate all certificates.
func (ssa *SQLStorageAuthority) GetCertificateByShortSerial(shortSerial string) (cert core.Certificate, err error) {
	if len(shortSerial) != 16 {
		err = errors.New("Invalid certificate short serial " + shortSerial)
		return
	}

	err = ssa.dbMap.SelectOne(&cert, "SELECT * FROM certificates WHERE serial LIKE :shortSerial",
		map[string]interface{}{"shortSerial": shortSerial + "%"})
	return
}

// GetCertificate takes a serial number and returns the corresponding
// certificate, or error if it does not exist.
func (ssa *SQLStorageAuthority) GetCertificate(serial string) (core.Certificate, error) {
	if len(serial) != 32 {
		err := fmt.Errorf("Invalid certificate serial %s", serial)
		return core.Certificate{}, err
	}

	certObj, err := ssa.dbMap.Get(core.Certificate{}, serial)
	if err != nil {
		return core.Certificate{}, err
	}
	if certObj == nil {
		ssa.log.Debug(fmt.Sprintf("Nil cert for %s", serial))
		return core.Certificate{}, fmt.Errorf("Certificate does not exist for %s", serial)
	}

	certPtr, ok := certObj.(*core.Certificate)
	if !ok {
		ssa.log.Debug("Failed to convert cert")
		return core.Certificate{}, fmt.Errorf("Error converting certificate response for %s", serial)
	}
	return *certPtr, err
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

// NewRegistration stores a new Registration
func (ssa *SQLStorageAuthority) NewRegistration(reg core.Registration) (core.Registration, error) {
	rm, err := registrationToModel(&reg)
	if err != nil {
		return reg, err
	}
	err = ssa.dbMap.Insert(rm)
	if err != nil {
		return reg, err
	}
	return modelToRegistration(rm)
}

// UpdateOCSP stores an updated OCSP response.
func (ssa *SQLStorageAuthority) UpdateOCSP(serial string, ocspResponse []byte) (err error) {
	status, err := ssa.GetCertificateStatus(serial)
	if err != nil {
		return fmt.Errorf(
			"Unable to update OCSP for certificate %s: cert status not found.", serial)
	}

	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return
	}

	timeStamp := time.Now()

	// Record the response.
	ocspResp := &core.OCSPResponse{Serial: serial, CreatedAt: timeStamp, Response: ocspResponse}
	err = tx.Insert(ocspResp)
	if err != nil {
		tx.Rollback()
		return err
	}

	// Reset the update clock
	status.OCSPLastUpdated = timeStamp
	_, err = tx.Update(&status)
	if err != nil {
		tx.Rollback()
		return err
	}

	err = tx.Commit()
	return
}

// MarkCertificateRevoked stores the fact that a certificate is revoked, along
// with a timestamp and a reason.
func (ssa *SQLStorageAuthority) MarkCertificateRevoked(serial string, ocspResponse []byte, reasonCode int) (err error) {
	if _, err = ssa.GetCertificate(serial); err != nil {
		return fmt.Errorf(
			"Unable to mark certificate %s revoked: cert not found.", serial)
	}

	if _, err = ssa.GetCertificateStatus(serial); err != nil {
		return fmt.Errorf(
			"Unable to mark certificate %s revoked: cert status not found.", serial)
	}

	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return
	}

	ocspResp := &core.OCSPResponse{Serial: serial, CreatedAt: time.Now(), Response: ocspResponse}
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

// UpdateRegistration stores an updated Registration
func (ssa *SQLStorageAuthority) UpdateRegistration(reg core.Registration) error {
	rm, err := registrationToModel(&reg)
	if err != nil {
		return err
	}

	n, err := ssa.dbMap.Update(rm)
	if err != nil {
		return err
	}
	if n == 0 {
		msg := fmt.Sprintf("Requested registration not found %v", reg.ID)
		return NoSuchRegistrationError{Msg: msg}
	}

	return nil
}

// NewPendingAuthorization stores a new Pending Authorization
func (ssa *SQLStorageAuthority) NewPendingAuthorization(authz core.Authorization) (output core.Authorization, err error) {
	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return
	}

	// Check that it doesn't exist already
	authz.ID = core.NewToken()
	for existingPending(tx, authz.ID) || existingFinal(tx, authz.ID) {
		authz.ID = core.NewToken()
	}

	// Insert a stub row in pending
	pendingAuthz := pendingauthzModel{Authorization: authz}
	err = tx.Insert(&pendingAuthz)
	if err != nil {
		tx.Rollback()
		return
	}

	for _, c := range authz.Challenges {
		chall, err := challengeToModel(&c, pendingAuthz.ID)
		if err != nil {
			tx.Rollback()
			return core.Authorization{}, err
		}
		err = tx.Insert(chall)
		if err != nil {
			tx.Rollback()
			return core.Authorization{}, err
		}
	}

	err = tx.Commit()
	output = pendingAuthz.Authorization
	output.Challenges = authz.Challenges
	return
}

// UpdatePendingAuthorization updates a Pending Authorization
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

	err = updateChallenges(authz.ID, authz.Challenges, tx)
	if err != nil {
		tx.Rollback()
		return
	}

	err = tx.Commit()
	return
}

// FinalizeAuthorization converts a Pending Authorization to a final one
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

	err = updateChallenges(authz.ID, authz.Challenges, tx)
	if err != nil {
		tx.Rollback()
		return
	}

	err = tx.Commit()
	return
}

// AddCertificate stores an issued certificate.
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
		Expires:        parsedCertificate.NotAfter,
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

	// TODO Verify that the serial number doesn't yet exist
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

// AlreadyDeniedCSR queries to find if the name list has already been denied.
func (ssa *SQLStorageAuthority) AlreadyDeniedCSR(names []string) (already bool, err error) {
	sort.Strings(names)

	var denied int64
	err = ssa.dbMap.SelectOne(
		&denied,
		"SELECT count(*) FROM deniedCSRs WHERE names = :names",
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
