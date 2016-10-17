package sa

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"time"

	jose "github.com/square/go-jose"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/revocation"
)

type dbSelectOne func(interface{}, string, ...interface{}) error
type dbSelect func(interface{}, string, ...interface{}) ([]interface{}, error)

const regFields = "id, jwk, jwk_sha256, contact, agreement, initialIP, createdAt, LockCol"
const regFieldsv2 = regFields + ", status"

func SelectRegistration(so dbSelectOne, q string, args ...interface{}) (*regModelv1, error) {
	var model regModelv1
	err := so(
		&model,
		"SELECT "+regFields+" FROM registrations "+q,
		args...,
	)
	return &model, err
}

func SelectRegistrationv2(so dbSelectOne, q string, args ...interface{}) (*regModelv2, error) {
	var model regModelv2
	err := so(
		&model,
		"SELECT "+regFieldsv2+" FROM registrations "+q, args...)
	return &model, err
}

func SelectPendingAuthz(so dbSelectOne, q string, args ...interface{}) (*pendingauthzModel, error) {
	var model pendingauthzModel
	err := so(
		&model,
		"SELECT id, identifier, registrationID, status, expires, combinations, LockCol FROM pendingAuthorizations "+q,
		args...,
	)
	return &model, err
}

const authzFields = "id, identifier, registrationID, status, expires, combinations"

func SelectAuthz(so dbSelectOne, q string, args ...interface{}) (*authzModel, error) {
	var model authzModel
	err := so(
		&model,
		"SELECT "+authzFields+" FROM authz "+q,
		args...,
	)
	return &model, err
}

func SelectAuthzs(s dbSelect, q string, args ...interface{}) ([]*core.Authorization, error) {
	var models []*core.Authorization
	_, err := s(
		&models,
		"SELECT "+authzFields+" FROM authz "+q,
		args...,
	)
	return models, err
}

func SelectSctReceipt(so dbSelectOne, q string, args ...interface{}) (core.SignedCertificateTimestamp, error) {
	var model core.SignedCertificateTimestamp
	err := so(
		&model,
		"SELECT id, sctVersion, logID, timestamp, extensions, signature, certificateSerial, LockCol FROM sctReceipts "+q,
		args...,
	)
	return model, err
}

const certFields = "registrationID, serial, digest, der, issued, expires"

func SelectCertificate(so dbSelectOne, q string, args ...interface{}) (core.Certificate, error) {
	var model core.Certificate
	err := so(
		&model,
		"SELECT "+certFields+" FROM certificates "+q,
		args...,
	)
	return model, err
}

func SelectCertificates(s dbSelect, q string, args map[string]interface{}) ([]core.Certificate, error) {
	var models []core.Certificate
	_, err := s(
		&models,
		"SELECT "+certFields+" FROM certificates "+q, args)
	return models, err
}

const certStatusFields = "serial, subscriberApproved, status, ocspLastUpdated, revokedDate, revokedReason, lastExpirationNagSent, ocspResponse, LockCol"
const certStatusFieldsv2 = certStatusFields + ", notAfter, isExpired"

func SelectCertificateStatus(so dbSelectOne, q string, args ...interface{}) (certStatusModelv1, error) {
	var model certStatusModelv1
	err := so(
		&model,
		"SELECT "+certStatusFields+" FROM certificateStatus "+q,
		args...,
	)
	return model, err
}

func SelectCertificateStatusv2(so dbSelectOne, q string, args ...interface{}) (certStatusModelv2, error) {
	var model certStatusModelv2
	err := so(
		&model,
		"SELECT "+certStatusFieldsv2+" FROM certificateStatus "+q,
		args...,
	)
	return model, err
}

func SelectCertificateStatuses(s dbSelect, q string, args ...interface{}) ([]core.CertificateStatus, error) {
	var models []core.CertificateStatus
	_, err := s(
		&models,
		"SELECT "+certStatusFields+" FROM certificateStatus "+q,
		args...,
	)
	return models, err
}

func SelectCertificateStatusesv2(s dbSelect, q string, args ...interface{}) ([]core.CertificateStatus, error) {
	var models []core.CertificateStatus
	_, err := s(
		&models,
		"SELECT "+certStatusFieldsv2+" FROM certificateStatus "+q,
		args...,
	)
	return models, err
}

var mediumBlobSize = int(math.Pow(2, 24))

type issuedNameModel struct {
	ID           int64     `db:"id"`
	ReversedName string    `db:"reversedName"`
	NotBefore    time.Time `db:"notBefore"`
	Serial       string    `db:"serial"`
}

// regModelv1 is the description of a core.Registration in the database before
// sa/_db/migrations/20160818140745_AddRegStatus.sql is applied
type regModelv1 struct {
	ID        int64    `db:"id"`
	Key       []byte   `db:"jwk"`
	KeySHA256 string   `db:"jwk_sha256"`
	Contact   []string `db:"contact"`
	Agreement string   `db:"agreement"`
	// InitialIP is stored as sixteen binary bytes, regardless of whether it
	// represents a v4 or v6 IP address.
	InitialIP []byte    `db:"initialIp"`
	CreatedAt time.Time `db:"createdAt"`
	LockCol   int64
}

// regModelv2 is the description of a core.Registration in the database after
// sa/_db/migrations/20160818140745_AddRegStatus.sql is applied
type regModelv2 struct {
	regModelv1
	Status string `db:"status"`
}

// We need two certStatus model structs, one for when boulder does *not* have
// the 20160817143417_CertStatusOptimizations.sql migration applied
// (certStatusModelv1) and one for when it does (certStatusModelv2)
//
// TODO(@cpu): Collapse into one struct once the migration has been applied
//             & feature flag set.
type certStatusModelv1 struct {
	Serial                string            `db:"serial"`
	SubscriberApproved    bool              `db:"subscriberApproved"`
	Status                core.OCSPStatus   `db:"status"`
	OCSPLastUpdated       time.Time         `db:"ocspLastUpdated"`
	RevokedDate           time.Time         `db:"revokedDate"`
	RevokedReason         revocation.Reason `db:"revokedReason"`
	LastExpirationNagSent time.Time         `db:"lastExpirationNagSent"`
	OCSPResponse          []byte            `db:"ocspResponse"`
	LockCol               int64             `json:"-"`
}

type certStatusModelv2 struct {
	certStatusModelv1
	NotAfter  time.Time `db:"notAfter"`
	IsExpired bool      `db:"isExpired"`
}

// challModel is the description of a core.Challenge in the database
//
// The Validation field is a stub; the column is only there for backward compatibility.
type challModel struct {
	ID              int64  `db:"id"`
	AuthorizationID string `db:"authorizationID"`

	Type   string          `db:"type"`
	Status core.AcmeStatus `db:"status"`
	Error  []byte          `db:"error"`
	// This field is unused, but is kept temporarily to avoid a database migration.
	// TODO(#1818): remove
	Validated        *time.Time `db:"validated"`
	Token            string     `db:"token"`
	KeyAuthorization string     `db:"keyAuthorization"`
	ValidationRecord []byte     `db:"validationRecord"`

	LockCol int64
}

// getChallengesQuery fetches exactly the fields in challModel from the
// challenges table.
const getChallengesQuery = `
	SELECT id, authorizationID, type, status, error, validated, token,
		keyAuthorization, validationRecord
	FROM challenges WHERE authorizationID = :authID ORDER BY id ASC`

// newReg creates a reg model object from a core.Registration
func registrationToModel(r *core.Registration) (interface{}, error) {
	key, err := json.Marshal(r.Key)
	if err != nil {
		return nil, err
	}

	sha, err := core.KeyDigest(r.Key)
	if err != nil {
		return nil, err
	}
	if r.InitialIP == nil {
		return nil, fmt.Errorf("initialIP was nil")
	}
	if r.Contact == nil {
		r.Contact = &[]string{}
	}
	rm := regModelv1{
		ID:        r.ID,
		Key:       key,
		KeySHA256: sha,
		Contact:   *r.Contact,
		Agreement: r.Agreement,
		InitialIP: []byte(r.InitialIP.To16()),
		CreatedAt: r.CreatedAt,
	}
	if features.Enabled(features.AllowAccountDeactivation) {
		return &regModelv2{
			regModelv1: rm,
			Status:     string(r.Status),
		}, nil
	}
	return &rm, nil
}

func modelToRegistration(ri interface{}) (core.Registration, error) {
	var rm *regModelv1
	if features.Enabled(features.AllowAccountDeactivation) {
		r2 := ri.(*regModelv2)
		rm = &r2.regModelv1
	} else {
		rm = ri.(*regModelv1)
	}
	k := &jose.JsonWebKey{}
	err := json.Unmarshal(rm.Key, k)
	if err != nil {
		err = fmt.Errorf("unable to unmarshal JsonWebKey in db: %s", err)
		return core.Registration{}, err
	}
	var contact *[]string
	// Contact can be nil when the DB contains the literal string "null". We
	// prefer to represent this in memory as a pointer to an empty slice rather
	// than a nil pointer.
	if rm.Contact == nil {
		contact = &[]string{}
	} else {
		contact = &rm.Contact
	}
	r := core.Registration{
		ID:        rm.ID,
		Key:       *k,
		Contact:   contact,
		Agreement: rm.Agreement,
		InitialIP: net.IP(rm.InitialIP),
		CreatedAt: rm.CreatedAt,
	}
	if features.Enabled(features.AllowAccountDeactivation) {
		r2 := ri.(*regModelv2)
		r.Status = core.AcmeStatus(r2.Status)
	}
	return r, nil
}

func challengeToModel(c *core.Challenge, authID string) (*challModel, error) {
	cm := challModel{
		ID:               c.ID,
		AuthorizationID:  authID,
		Type:             c.Type,
		Status:           c.Status,
		Token:            c.Token,
		KeyAuthorization: c.ProvidedKeyAuthorization,
	}
	if c.Error != nil {
		errJSON, err := json.Marshal(c.Error)
		if err != nil {
			return nil, err
		}
		if len(errJSON) > mediumBlobSize {
			return nil, fmt.Errorf("Error object is too large to store in the database")
		}
		cm.Error = errJSON
	}
	if len(c.ValidationRecord) > 0 {
		vrJSON, err := json.Marshal(c.ValidationRecord)
		if err != nil {
			return nil, err
		}
		if len(vrJSON) > mediumBlobSize {
			return nil, fmt.Errorf("Validation Record object is too large to store in the database")
		}
		cm.ValidationRecord = vrJSON
	}
	return &cm, nil
}

func modelToChallenge(cm *challModel) (core.Challenge, error) {
	c := core.Challenge{
		ID:     cm.ID,
		Type:   cm.Type,
		Status: cm.Status,
		Token:  cm.Token,
		ProvidedKeyAuthorization: cm.KeyAuthorization,
	}
	if len(cm.Error) > 0 {
		var problem probs.ProblemDetails
		err := json.Unmarshal(cm.Error, &problem)
		if err != nil {
			return core.Challenge{}, err
		}
		c.Error = &problem
	}
	if len(cm.ValidationRecord) > 0 {
		var vr []core.ValidationRecord
		err := json.Unmarshal(cm.ValidationRecord, &vr)
		if err != nil {
			return core.Challenge{}, err
		}
		c.ValidationRecord = vr
	}
	return c, nil
}
