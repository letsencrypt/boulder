// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sa

import (
	"encoding/json"
	"fmt"
	"math"
	"time"

	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
	"github.com/letsencrypt/boulder/core"
)

var mediumBlobSize = int(math.Pow(2, 24))

type issuedNameModel struct {
	ID           int64     `db:"id"`
	ReversedName string    `db:"reversedName"`
	Issued       time.Time `db:"issued"`
	Serial       string    `db:"serial"`
	LockCol      int64
}

// regModel is the description of a core.Registration in the database.
type regModel struct {
	ID        int64           `db:"id"`
	Key       []byte          `db:"jwk"`
	KeySHA256 string          `db:"jwk_sha256"`
	Contact   []*core.AcmeURL `db:"contact"`
	Agreement string          `db:"agreement"`
	LockCol   int64
}

// challModel is the description of a core.Challenge in the database
type challModel struct {
	ID              int64  `db:"id"`
	AuthorizationID string `db:"authorizationID"`

	Type             string          `db:"type"`
	Status           core.AcmeStatus `db:"status"`
	Error            []byte          `db:"error"`
	Validated        *time.Time      `db:"validated"`
	Token            string          `db:"token"`
	TLS              *bool           `db:"tls"`
	Validation       []byte          `db:"validation"`
	ValidationRecord []byte          `db:"validationRecord"`
	AccountKey       []byte          `db:"accountKey"`

	LockCol int64
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
	rm := &regModel{
		ID:        r.ID,
		Key:       key,
		KeySHA256: sha,
		Contact:   r.Contact,
		Agreement: r.Agreement,
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
	if c.Validation != nil {
		cm.Validation = []byte(c.Validation.FullSerialize())
		if len(cm.Validation) > mediumBlobSize {
			return nil, fmt.Errorf("Validation object is too large to store in the database")
		}
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
	if len(cm.Validation) > 0 {
		val, err := jose.ParseSigned(string(cm.Validation))
		if err != nil {
			return core.Challenge{}, err
		}
		c.Validation = val
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
