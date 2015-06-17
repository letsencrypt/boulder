// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"crypto/rand"
	"encoding/hex"
	blog "github.com/letsencrypt/boulder/log"
)

func SimpleHTTPChallenge() Challenge {
	tls := true
	return Challenge{
		Type:   ChallengeTypeSimpleHTTP,
		Status: StatusPending,
		Token:  NewToken(),
		TLS:    &tls,
	}
}

func DvsniChallenge() Challenge {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)

	if err != nil {
		audit := blog.GetAuditLogger()
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		audit.EmergencyExit(err.Error())
	}

	return Challenge{
		Type:   ChallengeTypeDVSNI,
		Status: StatusPending,
		R:      RandomString(32),
		Nonce:  hex.EncodeToString(nonce),
	}
}

func DNSChallenge() Challenge {
	return Challenge{
		Type:   ChallengeTypeDNS,
		Status: StatusPending,
		Token:  NewToken(),
	}
}
