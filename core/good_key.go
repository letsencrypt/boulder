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
var smallPrimeInts = []int64{
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
	53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
	109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
	173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
	233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
	293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359,
	367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431,
	433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491,
	499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571,
	577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641,
	643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709,
	719, 727, 733, 739, 743, 751,
}

// singleton defines the object of a Singleton pattern
var (
	smallPrimesSingleton sync.Once
	smallPrimes          []*big.Int
)

// GoodKey returns true iff the key is acceptable for both TLS use and account
// key use (our requirements are the same for either one), according to basic
// strength and algorithm checking.
// TODO: Support JsonWebKeys once go-jose migration is done.
func GoodKey(key crypto.PublicKey) error {
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
		err := MalformedRequestError(fmt.Sprintf("Unknown key type %s", reflect.TypeOf(key)))
		log.Debug(err.Error())
		return err
	}
}

// GoodKeyECDSA determines if an ECDSA pubkey meets our requirements
func GoodKeyECDSA(key ecdsa.PublicKey) (err error) {
	log := blog.GetAuditLogger()
	err = NotSupportedError("ECDSA keys not yet supported")
	log.Debug(err.Error())
	return
}

// GoodKeyRSA determines if a RSA pubkey meets our requirements
func GoodKeyRSA(key rsa.PublicKey) (err error) {
	log := blog.GetAuditLogger()
	// Baseline Requirements Appendix A
	// Modulus must be >= 2048 bits and <= 4096 bits
	modulus := key.N
	modulusBitLen := modulus.BitLen()
	const maxKeySize = 4096
	if modulusBitLen < 2048 {
		err = MalformedRequestError(fmt.Sprintf("Key too small: %d", modulusBitLen))
		log.Debug(err.Error())
		return err
	}
	if modulusBitLen > maxKeySize {
		err = MalformedRequestError(fmt.Sprintf("Key too large: %d > %d", modulusBitLen, maxKeySize))
		log.Debug(err.Error())
		return err
	}
	// The CA SHALL confirm that the value of the public exponent is an
	// odd number equal to 3 or more. Additionally, the public exponent
	// SHOULD be in the range between 2^16 + 1 and 2^256-1.
	// NOTE: rsa.PublicKey cannot represent an exponent part greater than
	// 2^32 - 1 or 2^64 - 1, because it stores E as an integer. So we
	// don't need to check the upper bound.
	if (key.E%2) == 0 || key.E < ((1<<16)+1) {
		err = MalformedRequestError(fmt.Sprintf("Key exponent should be odd and >2^16: %d", key.E))
		log.Debug(err.Error())
		return err
	}
	// The modulus SHOULD also have the following characteristics: an odd
	// number, not the power of a prime, and have no factors smaller than 752.
	// TODO: We don't yet check for "power of a prime."
	smallPrimesSingleton.Do(func() {
		for _, prime := range smallPrimeInts {
			smallPrimes = append(smallPrimes, big.NewInt(prime))
		}
	})
	for _, prime := range smallPrimes {
		var result big.Int
		result.Mod(modulus, prime)
		if result.Sign() == 0 {
			err = MalformedRequestError(fmt.Sprintf("Key divisible by small prime: %d", prime))
			log.Debug(err.Error())
			return err
		}
	}
	return nil
}
