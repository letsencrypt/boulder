package ratelimits

import (
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/test"
)

const (
	tenZeroZeroOne = "10.0.0.1"
	tenZeroZeroTwo = "10.0.0.2"
)

// newTestLimiter makes a new limiter with the following configuration:
//   - 'NewRegistrationsPerIPAddress' burst: 20 count: 20 period: 1s
func newTestLimiter(t *testing.T) (*Limiter, clock.FakeClock) {
	clk := clock.NewFake()
	l, err := NewLimiter(clk, newInmem(), "testdata/working_default.yml", "")
	test.AssertNotError(t, err, "should not error")
	return l, clk
}

// newTestLimiterWithOverrides makes a new limiter with the following
// configuration:
//   - 'NewRegistrationsPerIPAddress' burst: 20 count: 20 period: 1s
//   - 'NewRegistrationsPerIPAddress:10.0.0.2' burst: 40 count: 40 period: 1s
func newTestLimiterWithOverrides(t *testing.T) (*Limiter, clock.FakeClock) {
	clk := clock.NewFake()
	l, err := NewLimiter(clk, newInmem(), "testdata/working_default.yml", "testdata/working_override.yml")
	test.AssertNotError(t, err, "should not error")
	return l, clk
}

func Test_Limiter_initialization_via_Check_and_Spend(t *testing.T) {
	l, _ := newTestLimiter(t)

	// Check on an empty bucket should initialize it and return the theoretical
	// next state of that bucket if the cost were spent.
	d, err := l.Check(NewRegistrationsPerIPAddress, tenZeroZeroOne, 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(19))
	// Verify our ResetIn timing is correct. 1 second == 1000 milliseconds and
	// 1000/20 = 50 milliseconds per request.
	test.AssertEquals(t, d.ResetIn, time.Millisecond*50)
	test.AssertEquals(t, d.RetryIn, time.Duration(0))

	// However, that cost should not be spent yet, a 0 cost check should tell us
	// that we actually have 20 remaining.
	d, err = l.Check(NewRegistrationsPerIPAddress, tenZeroZeroOne, 0)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(20))
	test.AssertEquals(t, d.ResetIn, time.Duration(0))
	test.AssertEquals(t, d.RetryIn, time.Duration(0))

	// Reset our bucket.
	err = l.Reset(NewRegistrationsPerIPAddress, tenZeroZeroOne)
	test.AssertNotError(t, err, "should not error")

	// Similar to above, but we'll use Spend() instead of Check() to initialize
	// the bucket. Spend should return the same result as Check.
	d, err = l.Spend(NewRegistrationsPerIPAddress, tenZeroZeroOne, 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(19))
	// Verify our ResetIn timing is correct. 1 second == 1000 milliseconds and
	// 1000/20 = 50 milliseconds per request.
	test.AssertEquals(t, d.ResetIn, time.Millisecond*50)
	test.AssertEquals(t, d.RetryIn, time.Duration(0))

	// However, that cost should not be spent yet, a 0 cost check should tell us
	// that we actually have 19 remaining.
	d, err = l.Check(NewRegistrationsPerIPAddress, tenZeroZeroOne, 0)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(19))
	// Verify our ResetIn is correct. 1 second == 1000 milliseconds and
	// 1000/20 = 50 milliseconds per request.
	test.AssertEquals(t, d.ResetIn, time.Millisecond*50)
	test.AssertEquals(t, d.RetryIn, time.Duration(0))
}

func Test_Limiter_Refund_and_Spend_cost_err(t *testing.T) {
	l, _ := newTestLimiter(t)

	// Spend a cost of 0, which should fail.
	_, err := l.Spend(NewRegistrationsPerIPAddress, tenZeroZeroOne, 0)
	test.AssertErrorIs(t, err, ErrInvalidCost)

	// Spend a negative cost, which should fail.
	_, err = l.Spend(NewRegistrationsPerIPAddress, tenZeroZeroOne, -1)
	test.AssertErrorIs(t, err, ErrInvalidCost)

	// Refund a cost of 0, which should fail.
	_, err = l.Refund(NewRegistrationsPerIPAddress, tenZeroZeroOne, 0)
	test.AssertErrorIs(t, err, ErrInvalidCost)

	// Refund a negative cost, which should fail.
	_, err = l.Refund(NewRegistrationsPerIPAddress, tenZeroZeroOne, -1)
	test.AssertErrorIs(t, err, ErrInvalidCost)
}

func Test_Limiter_with_bad_limits_path(t *testing.T) {
	_, err := NewLimiter(clock.NewFake(), newInmem(), "testdata/does-not-exist.yml", "")
	test.AssertError(t, err, "should error")

	_, err = NewLimiter(clock.NewFake(), newInmem(), "testdata/defaults.yml", "testdata/does-not-exist.yml")
	test.AssertError(t, err, "should error")
}

func Test_Limiter_Check_bad_cost(t *testing.T) {
	l, _ := newTestLimiter(t)
	_, err := l.Check(NewRegistrationsPerIPAddress, tenZeroZeroOne, -1)
	test.AssertErrorIs(t, err, ErrInvalidCostForCheck)
}

func Test_Limiter_Check_limit_no_exist(t *testing.T) {
	l, _ := newTestLimiter(t)
	_, err := l.Check(Name(9999), tenZeroZeroOne, 1)
	test.AssertError(t, err, "should error")
}

func Test_Limiter_getLimit_no_exist(t *testing.T) {
	l, _ := newTestLimiter(t)
	_, err := l.getLimit(Name(9999), "")
	test.AssertError(t, err, "should error")
}

func Test_Limiter_with_defaults(t *testing.T) {
	l, clk := newTestLimiter(t)

	// Attempt to spend 21 requests (a cost > the limit burst capacity), this
	// should fail with a specific error.
	_, err := l.Spend(NewRegistrationsPerIPAddress, tenZeroZeroOne, 21)
	test.AssertErrorIs(t, err, ErrInvalidCostOverLimit)

	// Attempt to spend all 20 requests, this should succeed.
	d, err := l.Spend(NewRegistrationsPerIPAddress, tenZeroZeroOne, 20)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(0))
	test.AssertEquals(t, d.ResetIn, time.Second)

	// Attempting to spend 1 more, this should fail.
	d, err = l.Spend(NewRegistrationsPerIPAddress, tenZeroZeroOne, 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, !d.Allowed, "should not be allowed")
	test.AssertEquals(t, d.Remaining, int64(0))
	test.AssertEquals(t, d.ResetIn, time.Second)

	// Verify our ResetIn is correct. 1 second == 1000 milliseconds and
	// 1000/20 = 50 milliseconds per request.
	test.AssertEquals(t, d.RetryIn, time.Millisecond*50)

	// Wait 50 milliseconds and try again.
	clk.Add(d.RetryIn)

	// We should be allowed to spend 1 more request.
	d, err = l.Spend(NewRegistrationsPerIPAddress, tenZeroZeroOne, 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(0))
	test.AssertEquals(t, d.ResetIn, time.Second)

	// Wait 1 second for a full bucket reset.
	clk.Add(d.ResetIn)

	// Quickly spend 20 requests in a row.
	for i := 0; i < 20; i++ {
		d, err = l.Spend(NewRegistrationsPerIPAddress, tenZeroZeroOne, 1)
		test.AssertNotError(t, err, "should not error")
		test.Assert(t, d.Allowed, "should be allowed")
		test.AssertEquals(t, d.Remaining, int64(19-i))
	}

	// Attempting to spend 1 more, this should fail.
	d, err = l.Spend(NewRegistrationsPerIPAddress, tenZeroZeroOne, 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, !d.Allowed, "should not be allowed")
	test.AssertEquals(t, d.Remaining, int64(0))
	test.AssertEquals(t, d.ResetIn, time.Second)
}

func Test_Limiter_with_limit_overrides(t *testing.T) {
	l, clk := newTestLimiterWithOverrides(t)

	// Attempt to check a spend of 41 requests (a cost > the limit burst
	// capacity), this should fail with a specific error.
	_, err := l.Check(NewRegistrationsPerIPAddress, tenZeroZeroTwo, 41)
	test.AssertErrorIs(t, err, ErrInvalidCostOverLimit)

	// Attempt to spend 41 requests (a cost > the limit burst capacity), this
	// should fail with a specific error.
	_, err = l.Spend(NewRegistrationsPerIPAddress, tenZeroZeroTwo, 41)
	test.AssertErrorIs(t, err, ErrInvalidCostOverLimit)

	// Attempt to spend all 40 requests, this should succeed.
	d, err := l.Spend(NewRegistrationsPerIPAddress, tenZeroZeroTwo, 40)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")

	// Attempting to spend 1 more, this should fail.
	d, err = l.Spend(NewRegistrationsPerIPAddress, tenZeroZeroTwo, 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, !d.Allowed, "should not be allowed")
	test.AssertEquals(t, d.Remaining, int64(0))
	test.AssertEquals(t, d.ResetIn, time.Second)

	// Verify our ResetIn is correct. 1 second == 1000 milliseconds and
	// 1000/40 = 25 milliseconds per request.
	test.AssertEquals(t, d.RetryIn, time.Millisecond*25)

	// Wait 50 milliseconds and try again.
	clk.Add(d.RetryIn)

	// We should be allowed to spend 1 more request.
	d, err = l.Spend(NewRegistrationsPerIPAddress, tenZeroZeroTwo, 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(0))
	test.AssertEquals(t, d.ResetIn, time.Second)

	// Wait 1 second for a full bucket reset.
	clk.Add(d.ResetIn)

	// Quickly spend 40 requests in a row.
	for i := 0; i < 40; i++ {
		d, err = l.Spend(NewRegistrationsPerIPAddress, tenZeroZeroTwo, 1)
		test.AssertNotError(t, err, "should not error")
		test.Assert(t, d.Allowed, "should be allowed")
		test.AssertEquals(t, d.Remaining, int64(39-i))
	}

	// Attempting to spend 1 more, this should fail.
	d, err = l.Spend(NewRegistrationsPerIPAddress, tenZeroZeroTwo, 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, !d.Allowed, "should not be allowed")
	test.AssertEquals(t, d.Remaining, int64(0))
	test.AssertEquals(t, d.ResetIn, time.Second)
}

func Test_Limiter_with_new_clients(t *testing.T) {
	l, _ := newTestLimiter(t)

	// Attempt to spend all 20 requests, this should succeed.
	d, err := l.Spend(NewRegistrationsPerIPAddress, tenZeroZeroOne, 20)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(0))
	test.AssertEquals(t, d.ResetIn, time.Second)

	// Another new client, spend 1 and check our remaining.
	d, err = l.Spend(NewRegistrationsPerIPAddress, "10.0.0.100", 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(19))
	test.AssertEquals(t, d.RetryIn, time.Duration(0))

	// 1 second == 1000 milliseconds and 1000/20 = 50 milliseconds per request.
	test.AssertEquals(t, d.ResetIn, time.Millisecond*50)
}

func Test_Limiter_Refund_and_Reset(t *testing.T) {
	l, clk := newTestLimiter(t)

	// Attempt to spend all 20 requests, this should succeed.
	d, err := l.Spend(NewRegistrationsPerIPAddress, tenZeroZeroOne, 20)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(0))
	test.AssertEquals(t, d.ResetIn, time.Second)

	// Refund 10 requests.
	d, err = l.Refund(NewRegistrationsPerIPAddress, tenZeroZeroOne, 10)
	test.AssertNotError(t, err, "should not error")
	test.AssertEquals(t, d.Remaining, int64(10))

	// Spend 10 requests, this should succeed.
	d, err = l.Spend(NewRegistrationsPerIPAddress, tenZeroZeroOne, 10)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(0))
	test.AssertEquals(t, d.ResetIn, time.Second)

	err = l.Reset(NewRegistrationsPerIPAddress, tenZeroZeroOne)
	test.AssertNotError(t, err, "should not error")

	// Attempt to spend 20 more requests, this should succeed.
	d, err = l.Spend(NewRegistrationsPerIPAddress, tenZeroZeroOne, 20)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(0))
	test.AssertEquals(t, d.ResetIn, time.Second)

	// Reset to full.
	clk.Add(d.ResetIn)

	// Refund 1 requests above our limit, this should fail.
	d, err = l.Refund(NewRegistrationsPerIPAddress, tenZeroZeroOne, 1)
	test.AssertErrorIs(t, err, ErrBucketAlreadyFull)
	test.AssertEquals(t, d.Remaining, int64(20))
}

func Test_Limiter_Check_Spend_parity(t *testing.T) {
	il, _ := newTestLimiter(t)
	jl, _ := newTestLimiter(t)
	i, err := il.Check(NewRegistrationsPerIPAddress, tenZeroZeroOne, 1)
	test.AssertNotError(t, err, "should not error")
	j, err := jl.Spend(NewRegistrationsPerIPAddress, tenZeroZeroOne, 1)
	test.AssertNotError(t, err, "should not error")
	test.AssertDeepEquals(t, i.Remaining, j.Remaining)
}
