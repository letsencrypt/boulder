// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sa

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"time"

	ct "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/google/certificate-transparency/go"
	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"

	"github.com/letsencrypt/boulder/core"
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
	ID        int64           `db:"id"`
	Key       []byte          `db:"jwk"`
	KeySHA256 string          `db:"jwk_sha256"`
	Contact   []*core.AcmeURL `db:"contact"`
	Agreement string          `db:"agreement"`
	// InitialIP is stored as sixteen binary bytes, regardless of whether it
	// represents a v4 or v6 IP address.
	InitialIP []byte    `db:"initialIp"`
	CreatedAt time.Time `db:"createdAt"`
	LockCol   int64
}

// challModel is the description of a core.Challenge in the database
//
// The Validation field is a stub; the column is only there for backward compatibility.
type challModel struct {
	ID              int64  `db:"id"`
	AuthorizationID string `db:"authorizationID"`

	Type             string          `db:"type"`
	Status           core.AcmeStatus `db:"status"`
	Error            []byte          `db:"error"`
	Validated        *time.Time      `db:"validated"`
	Token            string          `db:"token"`
	TLS              *bool           `db:"tls"`
	KeyAuthorization string          `db:"keyAuthorization"`
	ValidationRecord []byte          `db:"validationRecord"`
	AccountKey       []byte          `db:"accountKey"`

	LockCol int64
}

type sctModel struct {
	ID int64 `db:"id"`

	Version    uint8  `db:"sctVersion"`
	LogID      string `db:"logID"`
	Timestamp  uint64 `db:"timestamp"`
	Extensions []byte `db:"extensions"`
	Signature  []byte `db:"signature"`

	CertificateSerial string `db:"certificateSerial"`

	LockCol int64
}

func sctToModel(sct *ct.SignedCertificateTimestamp, serial string) (*sctModel, error) {
	sig, err := ct.MarshalDigitallySigned(sct.Signature)
	if err != nil {
		return nil, err
	}
	sm := &sctModel{
		CertificateSerial: serial,
		Version:           uint8(sct.SCTVersion),
		LogID:             sct.LogID.Base64String(),
		Timestamp:         sct.Timestamp,
		Extensions:        sct.Extensions,
		Signature:         sig,
	}
	fmt.Println("DOOPDOOP", sm.LogID)
	return sm, nil
}

func modelToSCT(sm *sctModel) (*ct.SignedCertificateTimestamp, error) {
	sig, err := ct.UnmarshalDigitallySigned(bytes.NewReader(sm.Signature))
	if err != nil {
		return nil, err
	}
	sct := &ct.SignedCertificateTimestamp{
		SCTVersion: ct.Version(sm.Version),
		Timestamp:  sm.Timestamp,
		Extensions: sm.Extensions,
		Signature:  *sig,
	}
	err = sct.LogID.FromBase64String(sm.LogID)
	if err != nil {
		return nil, err
	}
	return sct, nil
}

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
	rm := &regModel{
		ID:        r.ID,
		Key:       key,
		KeySHA256: sha,
		Contact:   r.Contact,
		Agreement: r.Agreement,
		InitialIP: []byte(r.InitialIP.To16()),
		CreatedAt: r.CreatedAt,
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
	r := core.Registration{
		ID:        rm.ID,
		Key:       *k,
		Contact:   rm.Contact,
		Agreement: rm.Agreement,
		InitialIP: net.IP(rm.InitialIP),
		CreatedAt: rm.CreatedAt,
	}
	return r, nil
}

func challengeToModel(c *core.Challenge, authID string) (*challModel, error) {
	cm := challModel{
		ID:              c.ID,
		AuthorizationID: authID,
		Type:            c.Type,
		Status:          c.Status,
		Validated:       c.Validated,
		Token:           c.Token,
		TLS:             c.TLS,
	}
	if c.KeyAuthorization != nil {
		kaString := c.KeyAuthorization.String()
		if len(kaString) > 255 {
			return nil, fmt.Errorf("Key authorization is too large to store in the database")
		}
		cm.KeyAuthorization = kaString
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
	if c.AccountKey != nil {
		akJSON, err := json.Marshal(c.AccountKey)
		if err != nil {
			return nil, err
		}
		if len(akJSON) > mediumBlobSize {
			return nil, fmt.Errorf("Account key object is too large to store in the database")
		}
		cm.AccountKey = akJSON
	}
	return &cm, nil
}

func modelToChallenge(cm *challModel) (core.Challenge, error) {
	c := core.Challenge{
		ID:        cm.ID,
		Type:      cm.Type,
		Status:    cm.Status,
		Validated: cm.Validated,
		Token:     cm.Token,
		TLS:       cm.TLS,
	}
	if len(cm.KeyAuthorization) > 0 {
		ka, err := core.NewKeyAuthorizationFromString(cm.KeyAuthorization)
		if err != nil {
			return core.Challenge{}, err
		}
		c.KeyAuthorization = &ka
	}
	if len(cm.Error) > 0 {
		var problem core.ProblemDetails
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
	if len(cm.AccountKey) > 0 {
		var ak jose.JsonWebKey
		err := json.Unmarshal(cm.AccountKey, &ak)
		if err != nil {
			return core.Challenge{}, err
		}
		c.AccountKey = &ak
	}
	return c, nil
}
