// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"crypto/rand"
	"encoding/hex"
)

func SimpleHTTPSChallenge() Challenge {
	return Challenge{
		Status: StatusPending,
		Token:  NewToken(),
	}
}

func DvsniChallenge() Challenge {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	return Challenge{
		Status: StatusPending,
		R:      RandomString(32),
		Nonce:  hex.EncodeToString(nonce),
	}
}
