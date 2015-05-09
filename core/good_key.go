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
	"reflect"
	blog "github.com/letsencrypt/boulder/log"
)

// GoodKey returns true iff the key is acceptable for both TLS use and account
// key use (our requirements are the same for either one), according to basic
// strength and algorithm checking.
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
	if key.E % 2 == 0 {
		log.Debug(fmt.Sprintf("Key exponent is an even number: %d", key.E))
		return false
	}
	// Additionally, the public exponent SHOULD be in the range between
	// 2^16 + 1 and 2^256-1.
	// NOTE: rsa.PublicKey cannot represent an exponent part greater than
	// 2^256 - 1, because it stores E as an integer. So we don't check the upper
	// bound.
	if key.E < ((1 << 6) + 1)  {
		log.Debug(fmt.Sprintf("Key exponent is too small: %d", key.E))
		return false
	}
	// TODO: The modulus SHOULD also have the following
	// characteristics: an odd number, not the power of a prime,
	// and have no factors smaller than 752.
	return true
}
