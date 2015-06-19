// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"math/rand"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/test"
)

func TestEmptyRateLimit(t *testing.T) {
	rl := RateLimit{}
	test.Assert(t, rl.AcceptableNow(104563), "Empty rate limit rejected a request")
}

func TestLimitRequests(t *testing.T) {
	rl := NewRateLimit(1, 5, 5*time.Hour)
	test.Assert(t, rl.AcceptableNow(1), "Rate limit rejected valid request")
	test.Assert(t, rl.AcceptableNow(1), "Rate limit rejected valid request")
	test.Assert(t, rl.AcceptableNow(1), "Rate limit rejected valid request")
	test.Assert(t, rl.AcceptableNow(1), "Rate limit rejected valid request")
	test.Assert(t, rl.AcceptableNow(1), "Rate limit rejected valid request")
	test.Assert(t, !rl.AcceptableNow(1), "Rate limit accepted too many requests")
}

func TestLimitIDs(t *testing.T) {
	rl := NewRateLimit(5, 1, 5*time.Hour)
	test.Assert(t, rl.AcceptableNow(1), "Rate limit rejected valid request")
	test.Assert(t, rl.AcceptableNow(2), "Rate limit rejected valid request")
	test.Assert(t, rl.AcceptableNow(3), "Rate limit rejected valid request")
	test.Assert(t, rl.AcceptableNow(4), "Rate limit rejected valid request")
	test.Assert(t, rl.AcceptableNow(5), "Rate limit rejected valid request")
	test.Assert(t, !rl.AcceptableNow(6), "Rate limit accepted too many IDs")
}

func TestAgeOff(t *testing.T) {
	rl := NewRateLimit(1, 1, 1*time.Second)
	test.Assert(t, rl.AcceptableNow(1), "Rate limit rejected valid request")
	test.Assert(t, !rl.AcceptableNow(1), "Rate limit accepted too many requests")
	time.Sleep(2 * time.Second)
	test.Assert(t, rl.AcceptableNow(1), "Rate limit failed to age off a request")
}

func newRateLimit() RateLimit {
	// Test using a RateLimit of reasonable size
	// This structure should take around 800KB of memory
	//   400K ~= 10000 * 5 * sizeof(int64)
	// This can accommodate 50000 / 60 = ~800qps.
	return NewRateLimit(10000, 5, 1*time.Minute)
}

func BenchmarkAllocate(b *testing.B) {
	for i := 0; i < b.N; i += 1 {
		NewRateLimit(10000, 5, 1*time.Minute)
	}
}

func BenchmarkTrim(b *testing.B) {
	rl := newRateLimit()
	b.ResetTimer()
	for i := 0; i < b.N; i += 1 {
		rl.Trim()
	}
}

func BenchmarkRateLimitInsert(b *testing.B) {
	rl := newRateLimit()
	for i := 0; i < b.N; i += 1 {
		x := int64(rand.Intn(rl.numQueues))
		rl.AcceptableNow(x)
	}
}
