// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sa

import (
	"encoding/json"
	"errors"
	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
	"github.com/letsencrypt/boulder/core"
)

// BoulderTypeConverter is used by Gorp for storing objects in DB.
type BoulderTypeConverter struct{}

// ToDb converts a Boulder object to one suitable for the DB representation.
func (tc BoulderTypeConverter) ToDb(val interface{}) (interface{}, error) {
	switch t := val.(type) {
	case core.AcmeIdentifier, []core.Challenge, []core.AcmeURL, [][]int:
		jsonBytes, err := json.Marshal(t)
		if err != nil {
			return nil, err
		}
		return string(jsonBytes), nil
	case jose.JsonWebKey:
		// HACK: Some of our storage methods, like NewAuthorization, expect to
		// write to the DB with the default, empty key, so we treat it specially,
		// serializing to an empty string. TODO: Modify authorizations to refer
		// to a registration id, and make sure registration ids are always filled.
		// https://github.com/letsencrypt/boulder/issues/181
		if t.Key == nil {
			return "", nil
		}
		jsonBytes, err := t.MarshalJSON()
		if err != nil {
			return "", err
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

// FromDb converts a DB representation back into a Boulder object.
func (tc BoulderTypeConverter) FromDb(target interface{}) (gorp.CustomScanner, bool) {
	switch target.(type) {
	case *core.AcmeIdentifier, *[]core.Challenge, *[]core.AcmeURL, *[][]int, core.JsonBuffer:
		binder := func(holder, target interface{}) error {
			s, ok := holder.(*string)
			if !ok {
				return errors.New("FromDb: Unable to convert *string")
			}
			b := []byte(*s)
			return json.Unmarshal(b, target)
		}
		return gorp.CustomScanner{Holder: new(string), Target: target, Binder: binder}, true
	case *jose.JsonWebKey:
		binder := func(holder, target interface{}) error {
			s, ok := holder.(*string)
			if !ok {
				return errors.New("FromDb: Unable to convert *string")
			}
			b := []byte(*s)
			k := target.(*jose.JsonWebKey)
			if *s != "" {
				return k.UnmarshalJSON(b)
			} else {
				// HACK: Sometimes we can have an empty string the in the DB where a
				// key should be. We should fix that (see HACK above). In the meantime,
				// return the default JsonWebKey in such situations.
				// https://github.com/letsencrypt/boulder/issues/181
				return nil
			}
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
