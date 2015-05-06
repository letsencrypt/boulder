// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	blog "github.com/letsencrypt/boulder/log"
)

// GoodKey returns true iff the key is acceptable for both TLS use and account
// key use (our requirements are the same for either one), according to basic
// strength and algorithm checking.
func GoodKey(key crypto.PublicKey) bool {
	log := blog.GetAuditLogger()
	rsaKey, ok := key.(rsa.PublicKey)
	if !ok {
		log.Debug("Non-RSA keys not yet supported.")
		return false
	}
	// Baseline Requirements Appendix A
	// Modulus must be >= 2048 bits
	modulus := rsaKey.N
	if modulus.BitLen() < 2048 {
		log.Debug(fmt.Sprintf("Key too small: %d", modulus.BitLen()))
		return false
	}
	// The CA SHALL confirm that the value of the public exponent
	// is an odd number equal to 3 or more
	if rsaKey.E % 2 == 0 {
		log.Debug(fmt.Sprintf("Key exponent is an even number: %d", rsaKey.E))
		return false
	}
	// Additionally, the public exponent SHOULD be in the range between
	// 2^16 + 1 and 2^256-1.
	// NOTE: rsa.PublicKey cannot represent an exponent part greater than
	// 2^256 - 1, because it stores E as an integer. So we don't check the upper
	// bound.
	if rsaKey.E < ((1 << 6) + 1)  {
		log.Debug(fmt.Sprintf("Key exponent is too small: %d", rsaKey.E))
		return false
	}
	// TODO: The modulus SHOULD also have the following
	// characteristics: an odd number, not the power of a prime,
	// and have no factors smaller than 752.
	return true
}
