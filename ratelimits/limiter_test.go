package ratelimits

import (
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/test"
)

func Test_Limiter_with_defaults(t *testing.T) {
	clk := clock.NewFake()

	// Create a new limiter with our test configuration.
	// UsageRequestsPerIPv4Address: burst: 20 count: 20 period: 1s
	// UsageRequestsPerIPv4Address:10.0.0.2: burst: 40 count: 40 period: 1s
	l, err := NewLimiter("./test/defaults.yml", "./test/overrides.yml", clk)
	test.AssertNotError(t, err, "should not error")

	// Set our starting TAT to now; we should have 20 requests available.
	l.source.Set(UsageRequestsPerIPv4Address, "10.0.0.1", clk.Now())

	// Attempt to spend 21 requests (a cost > the limit burst capacity), this
	// should fail with a specific error.
	d, err := l.Spend(UsageRequestsPerIPv4Address, "10.0.0.1", 21)
	test.AssertErrorIs(t, err, ErrInvalidCostForLimit)

	// Attempt to spend all 20 requests, this should succeed.
	d, err = l.Spend(UsageRequestsPerIPv4Address, "10.0.0.1", 20)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")

	// Attempting to spend 1 more, this should fail.
	d, err = l.Spend(UsageRequestsPerIPv4Address, "10.0.0.1", 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, !d.Allowed, "should not be allowed")
	test.AssertEquals(t, d.Remaining, 0)
	test.AssertEquals(t, d.ResetIn, time.Second)

	// Verify our RetryIn timing is correct.
	// 1 second == 1000 milliseconds and 1000/20 = 50 milliseconds per request.
	test.AssertEquals(t, d.RetryIn, time.Millisecond*50)

	// Wait 50 milliseconds and try again.
	clk.Add(d.RetryIn)

	// We should be allowed to spend 1 more request.
	d, err = l.Spend(UsageRequestsPerIPv4Address, "10.0.0.1", 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, 0)
	test.AssertEquals(t, d.ResetIn, time.Second)

	// Wait 1 second for a full bucket reset.
	clk.Add(d.ResetIn)

	// Quickly spend 20 requests in a row.
	for i := 0; i < 20; i++ {
		d, err = l.Spend(UsageRequestsPerIPv4Address, "10.0.0.1", 1)
		test.AssertNotError(t, err, "should not error")
		test.Assert(t, d.Allowed, "should be allowed")
		test.AssertEquals(t, d.Remaining, 19-i)
	}

	// Attempting to spend 1 more, this should fail.
	d, err = l.Spend(UsageRequestsPerIPv4Address, "10.0.0.1", 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, !d.Allowed, "should not be allowed")
	test.AssertEquals(t, d.Remaining, 0)
	test.AssertEquals(t, d.ResetIn, time.Second)
}

func Test_Limiter_with_limit_overrides(t *testing.T) {
	clk := clock.NewFake()

	// Create a new limiter with our test configuration.
	// UsageRequestsPerIPv4Address: burst: 20 count: 20 period: 1s
	// UsageRequestsPerIPv4Address:10.0.0.2: burst: 40 count: 40 period: 1s
	l, err := NewLimiter("./test/defaults.yml", "./test/overrides.yml", clk)
	test.AssertNotError(t, err, "should not error")

	// Set our starting TAT to now; we should have 40 requests available.
	l.source.Set(UsageRequestsPerIPv4Address, "10.0.0.2", clk.Now())

	// Attempt to spend  41 requests (a cost > the limit burst capacity), this
	// should fail with a specific error.
	d, err := l.Spend(UsageRequestsPerIPv4Address, "10.0.0.2", 41)
	test.AssertErrorIs(t, err, ErrInvalidCostForLimit)

	// Attempt to spend all 40 requests, this should succeed.
	d, err = l.Spend(UsageRequestsPerIPv4Address, "10.0.0.2", 40)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")

	// Attempting to spend 1 more, this should fail.
	d, err = l.Spend(UsageRequestsPerIPv4Address, "10.0.0.2", 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, !d.Allowed, "should not be allowed")
	test.AssertEquals(t, d.Remaining, 0)
	test.AssertEquals(t, d.ResetIn, time.Second)

	// Verify our RetryIn timing is correct.
	// 1 second == 1000 milliseconds and 1000/40 = 25 milliseconds per request.
	test.AssertEquals(t, d.RetryIn, time.Millisecond*25)

	// Wait 50 milliseconds and try again.
	clk.Add(d.RetryIn)

	// We should be allowed to spend 1 more request.
	d, err = l.Spend(UsageRequestsPerIPv4Address, "10.0.0.2", 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, 0)
	test.AssertEquals(t, d.ResetIn, time.Second)

	// Wait 1 second for a full bucket reset.
	clk.Add(d.ResetIn)

	// Quickly spend 40 requests in a row.
	for i := 0; i < 40; i++ {
		d, err = l.Spend(UsageRequestsPerIPv4Address, "10.0.0.2", 1)
		test.AssertNotError(t, err, "should not error")
		test.Assert(t, d.Allowed, "should be allowed")
		test.AssertEquals(t, d.Remaining, 39-i)
	}

	// Attempting to spend 1 more, this should fail.
	d, err = l.Spend(UsageRequestsPerIPv4Address, "10.0.0.2", 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, !d.Allowed, "should not be allowed")
	test.AssertEquals(t, d.Remaining, 0)
	test.AssertEquals(t, d.ResetIn, time.Second)
}
