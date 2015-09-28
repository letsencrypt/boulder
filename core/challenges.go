// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"encoding/json"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
)

func newChallenge(challengeType string, accountKey *jose.JsonWebKey) (Challenge, error) {
	ak := AuthorizedKey{
		Token: NewToken(),
		Key:   accountKey,
	}

	jsonAK, err := json.Marshal(ak)
	if err != nil {
		return Challenge{}, err
	}

	return Challenge{
		Type:          challengeType,
		Status:        StatusPending,
		AccountKey:    accountKey,
		AuthorizedKey: jsonAK,
	}, nil
}

// SimpleHTTPChallenge constructs a random HTTP challenge
func SimpleHTTPChallenge(accountKey *jose.JsonWebKey) (Challenge, error) {
	chall, err := newChallenge(ChallengeTypeSimpleHTTP, accountKey)
	if err != nil {
		return Challenge{}, err
	}

	tls := true
	chall.TLS = &tls
	return chall, nil
}

// DvsniChallenge constructs a random DVSNI challenge
func DvsniChallenge(accountKey *jose.JsonWebKey) (Challenge, error) {
	return newChallenge(ChallengeTypeDVSNI, accountKey)
}

// DNSChallenge constructs a random DNS challenge
func DNSChallenge(accountKey *jose.JsonWebKey) (Challenge, error) {
	return newChallenge(ChallengeTypeDNS, accountKey)
}
