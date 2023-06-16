package ratelimits

import (
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/test"
)

func Test_maybeSpend(t *testing.T) {
	clk := clock.NewFake()
	limit := RateLimit{Burst: 10, Count: 1, Period: config.Duration{Duration: time.Second}}

	// Begin by using 1 of our 10 requests.
	r := maybeSpend(clk, limit, clk.Now(), 1)
	test.Assert(t, r.Allowed, "should be allowed")
	test.AssertEquals(t, r.Remaining, 9)
	test.AssertEquals(t, r.RetryIn, time.Duration(0))
	test.AssertEquals(t, r.ResetIn, time.Second)

	// Immediately use another 9 of our remaining requests.
	r = maybeSpend(clk, limit, r.TAT, 9)
	test.Assert(t, r.Allowed, "should be allowed")
	test.AssertEquals(t, r.Remaining, 0)
	test.AssertEquals(t, r.RetryIn, time.Second)
	test.AssertEquals(t, r.ResetIn, time.Second*10)

	// Our new TAT should be 10 seconds (limit.Burst) in the future.
	test.AssertEquals(t, r.TAT, clk.Now().Add(time.Second*10))

	// Let's try using just 1 more request without waiting.
	r = maybeSpend(clk, limit, r.TAT, 1)
	test.Assert(t, !r.Allowed, "should not be allowed")
	test.AssertEquals(t, r.Remaining, 0)
	test.AssertEquals(t, r.RetryIn, time.Second)
	test.AssertEquals(t, r.ResetIn, time.Second*10)

	// Let's try being exactly as patient as we're told to be.
	clk.Add(r.RetryIn)

	// We are 1 second in the future, we should have 1 new request.
	r = maybeSpend(clk, limit, r.TAT, 1)
	test.Assert(t, r.Allowed, "should be allowed")
	test.AssertEquals(t, r.Remaining, 0)
	test.AssertEquals(t, r.RetryIn, time.Second)
	test.AssertEquals(t, r.ResetIn, time.Second*10)

	// Let's try waiting (10 seconds) for our whole bucket to refill.
	clk.Add(r.ResetIn)

	// We should have 10 new requests. If we use 1 we should have 9 remaining.
	r = maybeSpend(clk, limit, r.TAT, 1)
	test.Assert(t, r.Allowed, "should be allowed")
	test.AssertEquals(t, r.Remaining, 9)
	test.AssertEquals(t, r.RetryIn, time.Duration(0))
	test.AssertEquals(t, r.ResetIn, time.Second)

	// Have you ever tried spending 0, like, just to see what happens?
	r = maybeSpend(clk, limit, r.TAT, 0)
	test.Assert(t, r.Allowed, "should be allowed")
	test.AssertEquals(t, r.Remaining, 9)
	test.AssertEquals(t, r.RetryIn, time.Duration(0))
	test.AssertEquals(t, r.ResetIn, time.Second)

	// Spending 0 simply informed us that we still have 9 remaining, let's see
	// what we have after waiting 20 hours.
	clk.Add(20 * time.Hour)

	// C'mon, big money, no whammies, no whammies, STOP!
	r = maybeSpend(clk, limit, r.TAT, 0)
	test.Assert(t, r.Allowed, "should be allowed")
	test.AssertEquals(t, r.Remaining, 10)
	test.AssertEquals(t, r.RetryIn, time.Duration(0))
	test.AssertEquals(t, r.ResetIn, time.Duration(0))

	// Turns out that the most we can accrue is 10 (limit.Burst). Let's empty
	// this bucket out so we can try something else.
	r = maybeSpend(clk, limit, r.TAT, 10)
	test.Assert(t, r.Allowed, "should be allowed")
	test.AssertEquals(t, r.Remaining, 0)
	test.AssertEquals(t, r.RetryIn, time.Second)
	test.AssertEquals(t, r.ResetIn, time.Second*10)

	// If you spend 0 while you have 0 you should get 0.
	r = maybeSpend(clk, limit, r.TAT, 0)
	test.Assert(t, !r.Allowed, "should not be allowed")
	test.AssertEquals(t, r.Remaining, 0)
	test.AssertEquals(t, r.RetryIn, time.Second)
	test.AssertEquals(t, r.ResetIn, time.Second*10)

	// We don't play by the rules, we spend 1 when we have 0.
	r = maybeSpend(clk, limit, r.TAT, 1)
	test.Assert(t, !r.Allowed, "should not be allowed")
	test.AssertEquals(t, r.Remaining, 0)
	test.AssertEquals(t, r.RetryIn, time.Second)
	test.AssertEquals(t, r.ResetIn, time.Second*10)

	// Okay, maybe we should play by the rules if we want to get anywhere.
	clk.Add(r.RetryIn)

	// Our patience pays off, we should have 1 new request. Let's use it.
	r = maybeSpend(clk, limit, r.TAT, 1)
	test.Assert(t, r.Allowed, "should be allowed")
	test.AssertEquals(t, r.Remaining, 0)
	test.AssertEquals(t, r.RetryIn, time.Second)
	test.AssertEquals(t, r.ResetIn, time.Second*10)
}
