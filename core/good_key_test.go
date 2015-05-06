// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"testing"
	"crypto/ecdsa"
	"github.com/letsencrypt/boulder/test"
	//"crypto/rsa"
)

func TestWrongKeyType(t *testing.T) {
	ecdsaKey := ecdsa.PublicKey{}
	test.Assert(t, !GoodKey(ecdsaKey), "Should have rejected ECDSA key.")
}

func TestWrongKeyType(t *testing.T) {
	ecdsaKey := ecdsa.PublicKey{}
	test.Assert(t, !GoodKey(ecdsaKey), "Should have rejected ECDSA key.")
}
