// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	blog "github.com/letsencrypt/boulder/log"
	"math/big"
	"reflect"
	"sync"
)

// To generate, run: primes 2 752 | tr '\n' ,
var smallPrimes = []int64{
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751,
}

// singleton defines the object of a Singleton pattern
type singleton struct {
	once sync.Once
	// The big.Int form of these primes, memoized to save conversion time.
	smallPrimesBigInts []*big.Int
}

var _Singleton singleton

// GoodKey returns true iff the key is acceptable for both TLS use and account
// key use (our requirements are the same for either one), according to basic
// strength and algorithm checking.
// TODO: Support JsonWebKeys once go-jose migration is done.
func GoodKey(key crypto.PublicKey) bool {
	log := blog.GetAuditLogger()
	switch t := key.(type) {
	case rsa.PublicKey:
		return GoodKeyRSA(t)
	case *rsa.PublicKey:
		return GoodKeyRSA(*t)
	case ecdsa.PublicKey:
		return GoodKeyECDSA(t)
	case *ecdsa.PublicKey:
		return GoodKeyECDSA(*t)
	default:
		log.Debug(fmt.Sprintf("Unknown key type %s", reflect.TypeOf(key)))
		return false
	}
}

func GoodKeyECDSA(key ecdsa.PublicKey) bool {
	log := blog.GetAuditLogger()
	log.Debug(fmt.Sprintf("ECDSA keys not yet supported."))
	return false
}

func GoodKeyRSA(key rsa.PublicKey) bool {
	log := blog.GetAuditLogger()
	// Baseline Requirements Appendix A
	// Modulus must be >= 2048 bits
	modulus := key.N
	if modulus.BitLen() < 2048 {
		log.Debug(fmt.Sprintf("Key too small: %d", modulus.BitLen()))
		return false
	}
	// The CA SHALL confirm that the value of the public exponent
	// is an odd number equal to 3 or more
	if key.E%2 == 0 {
		log.Debug(fmt.Sprintf("Key exponent is an even number: %d", key.E))
		return false
	}
	// Additionally, the public exponent SHOULD be in the range between
	// 2^16 + 1 and 2^256-1.
	// NOTE: rsa.PublicKey cannot represent an exponent part greater than
	// 2^256 - 1, because it stores E as an integer. So we don't check the upper
	// bound.
	if key.E < ((1 << 6) + 1) {
		log.Debug(fmt.Sprintf("Key exponent is too small: %d", key.E))
		return false
	}
	// The modulus SHOULD also have the following characteristics: an odd
	// number, not the power of a prime, and have no factors smaller than 752.
	// TODO: We don't yet check for "power of a prime."
	_Singleton.once.Do(func() {
		for _, prime := range smallPrimes {
			_Singleton.smallPrimesBigInts = append(_Singleton.smallPrimesBigInts, big.NewInt(prime))
		}
	})
	for _, prime := range _Singleton.smallPrimesBigInts {
		var result big.Int
		result.Mod(modulus, prime)
		if result.Sign() == 0 {
			log.Debug(fmt.Sprintf("Key divisible by small prime: %d", prime))
			return false
		}
	}
	return true
}
