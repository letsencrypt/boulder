package sa

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/probs"
	jose "github.com/square/go-jose"
)

var mediumBlobSize = int(math.Pow(2, 24))

type issuedNameModel struct {
	ID           int64     `db:"id"`
	ReversedName string    `db:"reversedName"`
	NotBefore    time.Time `db:"notBefore"`
	Serial       string    `db:"serial"`
}

// regModel is the description of a core.Registration in the database.
type regModel struct {
	ID        int64    `db:"id"`
	Key       []byte   `db:"jwk"`
	KeySHA256 string   `db:"jwk_sha256"`
	Contact   []string `db:"contact"`
	Agreement string   `db:"agreement"`
	// InitialIP is stored as sixteen binary bytes, regardless of whether it
	// represents a v4 or v6 IP address.
	InitialIP []byte    `db:"initialIp"`
	CreatedAt time.Time `db:"createdAt"`
	Status    string    `db:"status"`
	LockCol   int64
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

	// obsoleteTLS is obsoleted. Only used for simpleHTTP and simpleHTTP is
	// dead. Only still here because gorp complains if its gone and locks up if
	// its private.
	ObsoleteTLS *bool `db:"tls"`
}

// getChallengesQuery fetches exactly the fields in challModel from the
// challenges table.
const getChallengesQuery = `
	SELECT id, authorizationID, type, status, error, validated, token,
		keyAuthorization, validationRecord, tls
	FROM challenges WHERE authorizationID = :authID ORDER BY id ASC`

// newReg creates a reg model object from a core.Registration
func registrationToModel(r *core.Registration) (*regModel, error) {
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
	rm := &regModel{
		ID:        r.ID,
		Key:       key,
		KeySHA256: sha,
		Contact:   *r.Contact,
		Agreement: r.Agreement,
		InitialIP: []byte(r.InitialIP.To16()),
		CreatedAt: r.CreatedAt,
		Stats:     string(r.Status),
	}
	return rm, nil
}

func modelToRegistration(rm *regModel) (core.Registration, error) {
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
		Status:    core.AcmeStatus(rm.Status),
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
