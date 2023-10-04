package ratelimits

import (
	"context"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
	"github.com/prometheus/client_golang/prometheus"
)

// tenZeroZeroTwo is overridden in 'testdata/working_override.yml' to have
// higher burst and count values.
const tenZeroZeroTwo = "10.0.0.2"

// newTestLimiter constructs a new limiter with the following configuration:
//   - 'NewRegistrationsPerIPAddress' burst: 20 count: 20 period: 1s
//   - 'NewRegistrationsPerIPAddress:10.0.0.2' burst: 40 count: 40 period: 1s
func newTestLimiter(t *testing.T, s source, clk clock.FakeClock) *Limiter {
	l, err := NewLimiter(clk, s, "testdata/working_default.yml", "testdata/working_override.yml", metrics.NoopRegisterer)
	test.AssertNotError(t, err, "should not error")
	return l
}

func setup(t *testing.T) (context.Context, map[string]*Limiter, clock.FakeClock, string) {
	testCtx := context.Background()
	clk := clock.NewFake()

	// Generate a random IP address to avoid collisions during and between test
	// runs.
	randIP := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		randIP[i] = byte(rand.Intn(256))
	}

	// Construct a limiter for each source.
	return testCtx, map[string]*Limiter{
		"inmem": newInmemTestLimiter(t, clk),
		"redis": newRedisTestLimiter(t, clk),
	}, clk, randIP.String()
}

func Test_Limiter_WithBadLimitsPath(t *testing.T) {
	t.Parallel()
	_, err := NewLimiter(clock.NewFake(), newInmem(), "testdata/does-not-exist.yml", "", metrics.NoopRegisterer)
	test.AssertError(t, err, "should error")

	_, err = NewLimiter(clock.NewFake(), newInmem(), "testdata/defaults.yml", "testdata/does-not-exist.yml", metrics.NoopRegisterer)
	test.AssertError(t, err, "should error")
}

func Test_Limiter_getLimitNoExist(t *testing.T) {
	t.Parallel()
	l, err := NewLimiter(clock.NewFake(), newInmem(), "testdata/working_default.yml", "", metrics.NoopRegisterer)
	test.AssertNotError(t, err, "should not error")
	_, err = l.getLimit(Name(9999), "")
	test.AssertError(t, err, "should error")

}

func Test_Limiter_CheckWithLimitNoExist(t *testing.T) {
	t.Parallel()
	testCtx, limiters, _, testIP := setup(t)
	for name, l := range limiters {
		t.Run(name, func(t *testing.T) {
			_, err := l.Check(testCtx, Name(9999), testIP, 1)
			test.AssertError(t, err, "should error")
		})
	}
}

func Test_Limiter_CheckWithLimitOverrides(t *testing.T) {
	t.Parallel()
	testCtx, limiters, clk, _ := setup(t)
	for name, l := range limiters {
		t.Run(name, func(t *testing.T) {
			// Verify our overrideUsageGauge is being set correctly. 0.0 == 0% of
			// the bucket has been consumed.
			test.AssertMetricWithLabelsEquals(t, l.overrideUsageGauge, prometheus.Labels{
				"limit": NewRegistrationsPerIPAddress.String(), "client_id": tenZeroZeroTwo}, 0)

			// Attempt to check a spend of 41 requests (a cost > the limit burst
			// capacity), this should fail with a specific error.
			_, err := l.Check(testCtx, NewRegistrationsPerIPAddress, tenZeroZeroTwo, 41)
			test.AssertErrorIs(t, err, ErrInvalidCostOverLimit)

			// Attempt to spend 41 requests (a cost > the limit burst capacity),
			// this should fail with a specific error.
			_, err = l.Spend(testCtx, NewRegistrationsPerIPAddress, tenZeroZeroTwo, 41)
			test.AssertErrorIs(t, err, ErrInvalidCostOverLimit)

			// Attempt to spend all 40 requests, this should succeed.
			d, err := l.Spend(testCtx, NewRegistrationsPerIPAddress, tenZeroZeroTwo, 40)
			test.AssertNotError(t, err, "should not error")
			test.Assert(t, d.Allowed, "should be allowed")

			// Attempting to spend 1 more, this should fail.
			d, err = l.Spend(testCtx, NewRegistrationsPerIPAddress, tenZeroZeroTwo, 1)
			test.AssertNotError(t, err, "should not error")
			test.Assert(t, !d.Allowed, "should not be allowed")
			test.AssertEquals(t, d.Remaining, int64(0))
			test.AssertEquals(t, d.ResetIn, time.Second)

			// Verify our overrideUsageGauge is being set correctly. 1.0 == 100% of
			// the bucket has been consumed.
			test.AssertMetricWithLabelsEquals(t, l.overrideUsageGauge, prometheus.Labels{
				"limit_name": NewRegistrationsPerIPAddress.String(), "client_id": tenZeroZeroTwo}, 1.0)

			// Verify our RetryIn is correct. 1 second == 1000 milliseconds and
			// 1000/40 = 25 milliseconds per request.
			test.AssertEquals(t, d.RetryIn, time.Millisecond*25)

			// Wait 50 milliseconds and try again.
			clk.Add(d.RetryIn)

			// We should be allowed to spend 1 more request.
			d, err = l.Spend(testCtx, NewRegistrationsPerIPAddress, tenZeroZeroTwo, 1)
			test.AssertNotError(t, err, "should not error")
			test.Assert(t, d.Allowed, "should be allowed")
			test.AssertEquals(t, d.Remaining, int64(0))
			test.AssertEquals(t, d.ResetIn, time.Second)

			// Wait 1 second for a full bucket reset.
			clk.Add(d.ResetIn)

			// Quickly spend 40 requests in a row.
			for i := 0; i < 40; i++ {
				d, err = l.Spend(testCtx, NewRegistrationsPerIPAddress, tenZeroZeroTwo, 1)
				test.AssertNotError(t, err, "should not error")
				test.Assert(t, d.Allowed, "should be allowed")
				test.AssertEquals(t, d.Remaining, int64(39-i))
			}

			// Attempting to spend 1 more, this should fail.
			d, err = l.Spend(testCtx, NewRegistrationsPerIPAddress, tenZeroZeroTwo, 1)
			test.AssertNotError(t, err, "should not error")
			test.Assert(t, !d.Allowed, "should not be allowed")
			test.AssertEquals(t, d.Remaining, int64(0))
			test.AssertEquals(t, d.ResetIn, time.Second)

			// Reset between tests.
			err = l.Reset(testCtx, NewRegistrationsPerIPAddress, tenZeroZeroTwo)
			test.AssertNotError(t, err, "should not error")
		})
	}
}

func Test_Limiter_InitializationViaCheckAndSpend(t *testing.T) {
	t.Parallel()
	testCtx, limiters, _, testIP := setup(t)
	for name, l := range limiters {
		t.Run(name, func(t *testing.T) {
			// Check on an empty bucket should initialize it and return the
			// theoretical next state of that bucket if the cost were spent.
			d, err := l.Check(testCtx, NewRegistrationsPerIPAddress, testIP, 1)
			test.AssertNotError(t, err, "should not error")
			test.Assert(t, d.Allowed, "should be allowed")
			test.AssertEquals(t, d.Remaining, int64(19))
			// Verify our ResetIn timing is correct. 1 second == 1000
			// milliseconds and 1000/20 = 50 milliseconds per request.
			test.AssertEquals(t, d.ResetIn, time.Millisecond*50)
			test.AssertEquals(t, d.RetryIn, time.Duration(0))

			// However, that cost should not be spent yet, a 0 cost check should
			// tell us that we actually have 20 remaining.
			d, err = l.Check(testCtx, NewRegistrationsPerIPAddress, testIP, 0)
			test.AssertNotError(t, err, "should not error")
			test.Assert(t, d.Allowed, "should be allowed")
			test.AssertEquals(t, d.Remaining, int64(20))
			test.AssertEquals(t, d.ResetIn, time.Duration(0))
			test.AssertEquals(t, d.RetryIn, time.Duration(0))

			// Reset our bucket.
			err = l.Reset(testCtx, NewRegistrationsPerIPAddress, testIP)
			test.AssertNotError(t, err, "should not error")

			// Similar to above, but we'll use Spend() instead of Check() to
			// initialize the bucket. Spend should return the same result as
			// Check.
			d, err = l.Spend(testCtx, NewRegistrationsPerIPAddress, testIP, 1)
			test.AssertNotError(t, err, "should not error")
			test.Assert(t, d.Allowed, "should be allowed")
			test.AssertEquals(t, d.Remaining, int64(19))
			// Verify our ResetIn timing is correct. 1 second == 1000
			// milliseconds and 1000/20 = 50 milliseconds per request.
			test.AssertEquals(t, d.ResetIn, time.Millisecond*50)
			test.AssertEquals(t, d.RetryIn, time.Duration(0))

			// However, that cost should not be spent yet, a 0 cost check should
			// tell us that we actually have 19 remaining.
			d, err = l.Check(testCtx, NewRegistrationsPerIPAddress, testIP, 0)
			test.AssertNotError(t, err, "should not error")
			test.Assert(t, d.Allowed, "should be allowed")
			test.AssertEquals(t, d.Remaining, int64(19))
			// Verify our ResetIn is correct. 1 second == 1000 milliseconds and
			// 1000/20 = 50 milliseconds per request.
			test.AssertEquals(t, d.ResetIn, time.Millisecond*50)
			test.AssertEquals(t, d.RetryIn, time.Duration(0))
		})
	}
}

func Test_Limiter_RefundAndSpendCostErr(t *testing.T) {
	t.Parallel()
	testCtx, limiters, _, testIP := setup(t)
	for name, l := range limiters {
		t.Run(name, func(t *testing.T) {
			// Spend a cost of 0, which should fail.
			_, err := l.Spend(testCtx, NewRegistrationsPerIPAddress, testIP, 0)
			test.AssertErrorIs(t, err, ErrInvalidCost)

			// Spend a negative cost, which should fail.
			_, err = l.Spend(testCtx, NewRegistrationsPerIPAddress, testIP, -1)
			test.AssertErrorIs(t, err, ErrInvalidCost)

			// Refund a cost of 0, which should fail.
			_, err = l.Refund(testCtx, NewRegistrationsPerIPAddress, testIP, 0)
			test.AssertErrorIs(t, err, ErrInvalidCost)

			// Refund a negative cost, which should fail.
			_, err = l.Refund(testCtx, NewRegistrationsPerIPAddress, testIP, -1)
			test.AssertErrorIs(t, err, ErrInvalidCost)
		})
	}
}

func Test_Limiter_CheckWithBadCost(t *testing.T) {
	t.Parallel()
	testCtx, limiters, _, testIP := setup(t)
	for name, l := range limiters {
		t.Run(name, func(t *testing.T) {
			_, err := l.Check(testCtx, NewRegistrationsPerIPAddress, testIP, -1)
			test.AssertErrorIs(t, err, ErrInvalidCostForCheck)
		})
	}
}

func Test_Limiter_DefaultLimits(t *testing.T) {
	t.Parallel()
	testCtx, limiters, clk, testIP := setup(t)
	for name, l := range limiters {
		t.Run(name, func(t *testing.T) {
			// Attempt to spend 21 requests (a cost > the limit burst capacity),
			// this should fail with a specific error.
			_, err := l.Spend(testCtx, NewRegistrationsPerIPAddress, testIP, 21)
			test.AssertErrorIs(t, err, ErrInvalidCostOverLimit)

			// Attempt to spend all 20 requests, this should succeed.
			d, err := l.Spend(testCtx, NewRegistrationsPerIPAddress, testIP, 20)
			test.AssertNotError(t, err, "should not error")
			test.Assert(t, d.Allowed, "should be allowed")
			test.AssertEquals(t, d.Remaining, int64(0))
			test.AssertEquals(t, d.ResetIn, time.Second)

			// Attempting to spend 1 more, this should fail.
			d, err = l.Spend(testCtx, NewRegistrationsPerIPAddress, testIP, 1)
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
			d, err = l.Spend(testCtx, NewRegistrationsPerIPAddress, testIP, 1)
			test.AssertNotError(t, err, "should not error")
			test.Assert(t, d.Allowed, "should be allowed")
			test.AssertEquals(t, d.Remaining, int64(0))
			test.AssertEquals(t, d.ResetIn, time.Second)

			// Wait 1 second for a full bucket reset.
			clk.Add(d.ResetIn)

			// Quickly spend 20 requests in a row.
			for i := 0; i < 20; i++ {
				d, err = l.Spend(testCtx, NewRegistrationsPerIPAddress, testIP, 1)
				test.AssertNotError(t, err, "should not error")
				test.Assert(t, d.Allowed, "should be allowed")
				test.AssertEquals(t, d.Remaining, int64(19-i))
			}

			// Attempting to spend 1 more, this should fail.
			d, err = l.Spend(testCtx, NewRegistrationsPerIPAddress, testIP, 1)
			test.AssertNotError(t, err, "should not error")
			test.Assert(t, !d.Allowed, "should not be allowed")
			test.AssertEquals(t, d.Remaining, int64(0))
			test.AssertEquals(t, d.ResetIn, time.Second)
		})
	}
}

func Test_Limiter_RefundAndReset(t *testing.T) {
	t.Parallel()
	testCtx, limiters, clk, testIP := setup(t)
	for name, l := range limiters {
		t.Run(name, func(t *testing.T) {
			// Attempt to spend all 20 requests, this should succeed.
			d, err := l.Spend(testCtx, NewRegistrationsPerIPAddress, testIP, 20)
			test.AssertNotError(t, err, "should not error")
			test.Assert(t, d.Allowed, "should be allowed")
			test.AssertEquals(t, d.Remaining, int64(0))
			test.AssertEquals(t, d.ResetIn, time.Second)

			// Refund 10 requests.
			d, err = l.Refund(testCtx, NewRegistrationsPerIPAddress, testIP, 10)
			test.AssertNotError(t, err, "should not error")
			test.AssertEquals(t, d.Remaining, int64(10))

			// Spend 10 requests, this should succeed.
			d, err = l.Spend(testCtx, NewRegistrationsPerIPAddress, testIP, 10)
			test.AssertNotError(t, err, "should not error")
			test.Assert(t, d.Allowed, "should be allowed")
			test.AssertEquals(t, d.Remaining, int64(0))
			test.AssertEquals(t, d.ResetIn, time.Second)

			err = l.Reset(testCtx, NewRegistrationsPerIPAddress, testIP)
			test.AssertNotError(t, err, "should not error")

			// Attempt to spend 20 more requests, this should succeed.
			d, err = l.Spend(testCtx, NewRegistrationsPerIPAddress, testIP, 20)
			test.AssertNotError(t, err, "should not error")
			test.Assert(t, d.Allowed, "should be allowed")
			test.AssertEquals(t, d.Remaining, int64(0))
			test.AssertEquals(t, d.ResetIn, time.Second)

			// Reset to full.
			clk.Add(d.ResetIn)

			// Refund 1 requests above our limit, this should fail.
			d, err = l.Refund(testCtx, NewRegistrationsPerIPAddress, testIP, 1)
			test.AssertNotError(t, err, "should not error")
			test.Assert(t, !d.Allowed, "should not be allowed")
			test.AssertEquals(t, d.Remaining, int64(20))
		})
	}
}
