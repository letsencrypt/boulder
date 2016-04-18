// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"github.com/square/go-jose"
)

func newChallenge(challengeType string, accountKey *jose.JsonWebKey) Challenge {
	return Challenge{
		Type:       challengeType,
		Status:     StatusPending,
		AccountKey: accountKey,
		Token:      NewToken(),
	}
}

// HTTPChallenge01 constructs a random http-01 challenge
func HTTPChallenge01(accountKey *jose.JsonWebKey) Challenge {
	return newChallenge(ChallengeTypeHTTP01, accountKey)
}

// TLSSNIChallenge01 constructs a random tls-sni-00 challenge
func TLSSNIChallenge01(accountKey *jose.JsonWebKey) Challenge {
	return newChallenge(ChallengeTypeTLSSNI01, accountKey)
}

// DNSChallenge01 constructs a random DNS challenge
func DNSChallenge01(accountKey *jose.JsonWebKey) Challenge {
	return newChallenge(ChallengeTypeDNS01, accountKey)
}
