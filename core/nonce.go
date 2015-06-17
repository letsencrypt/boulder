// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"math/big"
)

// MaxUsed defines the maximum number of Nonces we're willing to hold in
// memory.
const MaxUsed = 65536

// NonceService generates, cancels, and tracks Nonces.
type NonceService struct {
	latest   int64
	earliest int64
	used     map[int64]bool
	gcm      cipher.AEAD
	maxUsed  int
}

// NewNonceService constructs a NonceService with defaults
func NewNonceService() NonceService {
	// XXX ignoring possible error due to entropy starvation
	key := make([]byte, 16)
	rand.Read(key)

	// It is safe to ignore these errors because they only happen
	// on key size and block size mismatches.
	c, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(c)

	return NonceService{
		earliest: 0,
		latest:   0,
		used:     make(map[int64]bool, MaxUsed),
		gcm:      gcm,
		maxUsed:  MaxUsed,
	}
}

func (ns NonceService) encrypt(counter int64) string {
	// Generate a nonce with upper 4 bytes zero
	// XXX ignoring possible error due to entropy starvation
	nonce := make([]byte, 12)
	for i := 0; i < 4; i++ {
		nonce[i] = 0
	}
	rand.Read(nonce[4:])

	// Encode counter to plaintext
	pt := make([]byte, 8)
	ctr := big.NewInt(counter)
	pad := 8 - len(ctr.Bytes())
	copy(pt[pad:], ctr.Bytes())

	// Encrypt
	ret := make([]byte, 32)
	ct := ns.gcm.Seal(nil, nonce, pt, nil)
	copy(ret, nonce[4:])
	copy(ret[8:], ct)
	return B64enc(ret)
}

func (ns NonceService) decrypt(nonce string) (int64, error) {
	decoded, err := B64dec(nonce)
	if err != nil {
		return 0, err
	}

	n := make([]byte, 12)
	for i := 0; i < 4; i++ {
		n[i] = 0
	}
	copy(n[4:], decoded[:8])

	pt, err := ns.gcm.Open(nil, n, decoded[8:], nil)
	if err != nil {
		return 0, err
	}

	ctr := big.NewInt(0)
	ctr.SetBytes(pt)
	return ctr.Int64(), nil
}

// Nonce provides a new Nonce.
func (ns *NonceService) Nonce() string {
	ns.latest++
	return ns.encrypt(ns.latest)
}

func (ns *NonceService) minUsed() int64 {
	min := ns.latest
	for t := range ns.used {
		if t < min {
			min = t
		}
	}
	return min
}

// Valid determines whether the provided Nonce string is valid, returning
// true if so.
func (ns *NonceService) Valid(nonce string) bool {
	c, err := ns.decrypt(nonce)
	if err != nil {
		return false
	}

	if c > ns.latest {
		return false
	}

	if c <= ns.earliest {
		return false
	}

	if ns.used[c] {
		return false
	}

	ns.used[c] = true
	if len(ns.used) > ns.maxUsed {
		ns.earliest = ns.minUsed()
		delete(ns.used, ns.earliest)
	}

	return true
}
