// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

// SimpleHTTPChallenge constructs a random HTTP challenge
func SimpleHTTPChallenge() Challenge {
	tls := true
	return Challenge{
		Type:   ChallengeTypeSimpleHTTP,
		Status: StatusPending,
		Token:  NewToken(),
		TLS:    &tls,
	}
}

// DvsniChallenge constructs a random DVSNI challenge
func DvsniChallenge() Challenge {
	return Challenge{
		Type:   ChallengeTypeDVSNI,
		Status: StatusPending,
		Token:  NewToken(),
	}
}

// DNSChallenge constructs a random DNS challenge
func DNSChallenge() Challenge {
	return Challenge{
		Type:   ChallengeTypeDNS,
		Status: StatusPending,
		Token:  NewToken(),
	}
}
