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
// TODO(https://github.com/letsencrypt/boulder/issues/894): Delete this method
func SimpleHTTPChallenge(accountKey *jose.JsonWebKey) (Challenge, error) {
	tls := true
	return Challenge{
		Type:       ChallengeTypeSimpleHTTP,
		Status:     StatusPending,
		Token:      NewToken(),
		TLS:        &tls,
		AccountKey: accountKey,
	}, nil
}

// DvsniChallenge constructs a random DVSNI challenge
// TODO(https://github.com/letsencrypt/boulder/issues/894): Delete this method
func DvsniChallenge(accountKey *jose.JsonWebKey) (Challenge, error) {
	return Challenge{
		Type:       ChallengeTypeDVSNI,
		Status:     StatusPending,
		Token:      NewToken(),
		AccountKey: accountKey,
	}, nil
}

// HTTPChallenge constructs a random http-00 challenge
func HTTPChallenge01(accountKey *jose.JsonWebKey) (Challenge, error) {
	chall, err := newChallenge(ChallengeTypeHTTP01, accountKey)
	if err != nil {
		return Challenge{}, err
	}

	tls := true
	chall.TLS = &tls
	return chall, nil
}

// DvsniChallenge constructs a random tls-sni-00 challenge
func TLSSNIChallenge01(accountKey *jose.JsonWebKey) (Challenge, error) {
	return newChallenge(ChallengeTypeTLSSNI01, accountKey)
}

// DNSChallenge constructs a random DNS challenge
func DNSChallenge01(accountKey *jose.JsonWebKey) (Challenge, error) {
	return newChallenge(ChallengeTypeDNS01, accountKey)
}
