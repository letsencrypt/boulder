// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"testing"
	"fmt"
	"github.com/letsencrypt/boulder/test"
	"math"
)

// challenges.go
func TestNewToken(t *testing.T) {
	token := NewToken()
	fmt.Println(token)
	tokenLength := int(math.Ceil(32 * 8 / 6.0)) // 32 bytes, b64 encoded
	test.AssertIntEquals(t,len(token),tokenLength)
	collider := map[string]bool{}
	// Test for very blatant RNG failures:
	// Try 2^20 birthdays in a 2^72 search space...
	// our naive collision probability here is  2^-32...
	for i:=0; i < 1000000; i++ {
		token = NewToken()[:12] // just sample a portion
		test.Assert(t,!collider[token],"Token collision!")
		collider[token] = true
	}
	return
}

func TestRandString(t *testing.T) {
  // This is covered by NewToken
  return
}
