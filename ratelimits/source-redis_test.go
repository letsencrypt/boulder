package ratelimits

import (
	"context"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"

	"github.com/go-redis/redis/v8"
	"github.com/jmhodges/clock"
)

const (
	tenZeroZeroThree = "10.0.0.3"
	tenZeroZeroFour  = "10.0.0.4"
	tenZeroZeroFive  = "10.0.0.5"
	tenZeroZeroSix   = "10.0.0.6"
	tenZeroZeroSeven = "10.0.0.7"
)

func makeClient() (*RedisSource, clock.FakeClock) {
	CACertFile := "../test/redis-tls/minica.pem"
	CertFile := "../test/redis-tls/boulder/cert.pem"
	KeyFile := "../test/redis-tls/boulder/key.pem"
	tlsConfig := cmd.TLSConfig{
		CACertFile: CACertFile,
		CertFile:   CertFile,
		KeyFile:    KeyFile,
	}
	tlsConfig2, err := tlsConfig.Load(metrics.NoopRegisterer)
	if err != nil {
		panic(err)
	}

	client := redis.NewRing(&redis.RingOptions{
		Addrs: map[string]string{
			"shard1": "10.33.33.4:4218",
			"shard2": "10.33.33.5:4218",
		},
		Username:  "unittest-rw",
		Password:  "824968fa490f4ecec1e52d5e34916bdb60d45f8d",
		TLSConfig: tlsConfig2,
	})
	clk := clock.NewFake()
	return NewRedisSource(client, 5*time.Second, clk, metrics.NoopRegisterer), clk
}

// newTestLimiter makes a new limiter with the following configuration:
//   - 'NewRegistrationsPerIPAddress' burst: 20 count: 20 period: 1s
func newRedisTestLimiter(t *testing.T) (*Limiter, clock.FakeClock, func(Name, string)) {
	source, clk := makeClient()
	l, err := NewLimiter(clk, source, "testdata/working_default.yml", "")
	test.AssertNotError(t, err, "should not error")
	return l, clk, func(name Name, id string) {
		err = l.Reset(context.Background(), name, id)
		if err != nil {
			t.Fatalf("failed to reset bucket: %v", err)
		}
	}
}

// newRedisTestLimiterWithOverrides makes a new limiter with the following
// configuration:
//   - 'NewRegistrationsPerIPAddress' burst: 20 count: 20 period: 1s
//   - 'NewRegistrationsPerIPAddress:10.0.0.2' burst: 40 count: 40 period: 1s
func newRedisTestLimiterWithOverrides(t *testing.T) (*Limiter, clock.FakeClock, func(Name, string)) {
	source, clk := makeClient()
	l, err := NewLimiter(clk, source, "testdata/working_default.yml", "testdata/working_override.yml")
	test.AssertNotError(t, err, "should not error")
	return l, clk, func(name Name, id string) {
		err = l.Reset(context.Background(), name, id)
		if err != nil {
			t.Fatalf("failed to reset bucket: %v", err)
		}
	}
}

func Test_Redis_Limiter_Refund_and_Spend_cost_err(t *testing.T) {
	t.Parallel()
	l, _, reset := newRedisTestLimiter(t)
	defer reset(NewRegistrationsPerIPAddress, tenZeroZeroOne)

	// Spend a cost of 0, which should fail.
	_, err := l.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroOne, 0)
	test.AssertErrorIs(t, err, ErrInvalidCost)

	// Spend a negative cost, which should fail.
	_, err = l.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroOne, -1)
	test.AssertErrorIs(t, err, ErrInvalidCost)

	// Refund a cost of 0, which should fail.
	_, err = l.Refund(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroOne, 0)
	test.AssertErrorIs(t, err, ErrInvalidCost)

	// Refund a negative cost, which should fail.
	_, err = l.Refund(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroOne, -1)
	test.AssertErrorIs(t, err, ErrInvalidCost)
}

func Test_Redis_Limiter_with_limit_overrides(t *testing.T) {
	t.Parallel()
	l, clk, reset := newRedisTestLimiterWithOverrides(t)
	defer reset(NewRegistrationsPerIPAddress, tenZeroZeroTwo)

	// Attempt to check a spend of 41 requests (a cost > the limit burst
	// capacity), this should fail with a specific error.
	_, err := l.Check(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroTwo, 41)
	test.AssertErrorIs(t, err, ErrInvalidCostOverLimit)

	// Attempt to spend 41 requests (a cost > the limit burst capacity), this
	// should fail with a specific error.
	_, err = l.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroTwo, 41)
	test.AssertErrorIs(t, err, ErrInvalidCostOverLimit)

	// Attempt to spend all 40 requests, this should succeed.
	d, err := l.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroTwo, 40)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")

	// Attempting to spend 1 more, this should fail.
	d, err = l.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroTwo, 1)
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
	d, err = l.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroTwo, 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(0))
	test.AssertEquals(t, d.ResetIn, time.Second)

	// Wait 1 second for a full bucket reset.
	clk.Add(d.ResetIn)

	// Quickly spend 40 requests in a row.
	for i := 0; i < 40; i++ {
		d, err = l.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroTwo, 1)
		test.AssertNotError(t, err, "should not error")
		test.Assert(t, d.Allowed, "should be allowed")
		test.AssertEquals(t, d.Remaining, int64(39-i))
	}

	// Attempting to spend 1 more, this should fail.
	d, err = l.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroTwo, 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, !d.Allowed, "should not be allowed")
	test.AssertEquals(t, d.Remaining, int64(0))
	test.AssertEquals(t, d.ResetIn, time.Second)
}

func Test_Redis_Limiter_initialization_via_Check_and_Spend(t *testing.T) {
	t.Parallel()
	l, _, reset := newRedisTestLimiter(t)
	defer reset(NewRegistrationsPerIPAddress, tenZeroZeroThree)

	// Check on an empty bucket should initialize it and return the theoretical
	// next state of that bucket if the cost were spent.
	d, err := l.Check(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroThree, 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(19))
	// Verify our ResetIn timing is correct. 1 second == 1000 milliseconds and
	// 1000/20 = 50 milliseconds per request.
	test.AssertEquals(t, d.ResetIn, time.Millisecond*50)
	test.AssertEquals(t, d.RetryIn, time.Duration(0))

	// However, that cost should not be spent yet, a 0 cost check should tell us
	// that we actually have 20 remaining.
	d, err = l.Check(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroThree, 0)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(20))
	test.AssertEquals(t, d.ResetIn, time.Duration(0))
	test.AssertEquals(t, d.RetryIn, time.Duration(0))

	// Reset our bucket.
	err = l.Reset(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroThree)
	test.AssertNotError(t, err, "should not error")

	// Similar to above, but we'll use Spend() instead of Check() to initialize
	// the bucket. Spend should return the same result as Check.
	d, err = l.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroThree, 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(19))
	// Verify our ResetIn timing is correct. 1 second == 1000 milliseconds and
	// 1000/20 = 50 milliseconds per request.
	test.AssertEquals(t, d.ResetIn, time.Millisecond*50)
	test.AssertEquals(t, d.RetryIn, time.Duration(0))

	// However, that cost should not be spent yet, a 0 cost check should tell us
	// that we actually have 19 remaining.
	d, err = l.Check(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroThree, 0)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(19))
	// Verify our ResetIn is correct. 1 second == 1000 milliseconds and
	// 1000/20 = 50 milliseconds per request.
	test.AssertEquals(t, d.ResetIn, time.Millisecond*50)
	test.AssertEquals(t, d.RetryIn, time.Duration(0))
}

func Test_Redis_Limiter_with_defaults(t *testing.T) {
	l, clk, reset := newRedisTestLimiter(t)
	defer reset(NewRegistrationsPerIPAddress, tenZeroZeroFour)

	// Attempt to spend 21 requests (a cost > the limit burst capacity), this
	// should fail with a specific error.
	_, err := l.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroFour, 21)
	test.AssertErrorIs(t, err, ErrInvalidCostOverLimit)

	// Attempt to spend all 20 requests, this should succeed.
	d, err := l.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroFour, 20)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(0))
	test.AssertEquals(t, d.ResetIn, time.Second)

	// Attempting to spend 1 more, this should fail.
	d, err = l.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroFour, 1)
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
	d, err = l.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroFour, 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(0))
	test.AssertEquals(t, d.ResetIn, time.Second)

	// Wait 1 second for a full bucket reset.
	clk.Add(d.ResetIn)

	// Quickly spend 20 requests in a row.
	for i := 0; i < 20; i++ {
		d, err = l.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroFour, 1)
		test.AssertNotError(t, err, "should not error")
		test.Assert(t, d.Allowed, "should be allowed")
		test.AssertEquals(t, d.Remaining, int64(19-i))
	}

	// Attempting to spend 1 more, this should fail.
	d, err = l.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroFour, 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, !d.Allowed, "should not be allowed")
	test.AssertEquals(t, d.Remaining, int64(0))
	test.AssertEquals(t, d.ResetIn, time.Second)
}

func Test_Redis_Limiter_Refund_and_Reset(t *testing.T) {
	t.Parallel()
	l, clk, reset := newRedisTestLimiter(t)
	defer reset(NewRegistrationsPerIPAddress, tenZeroZeroFive)

	// Attempt to spend all 20 requests, this should succeed.
	d, err := l.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroFive, 20)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(0))
	test.AssertEquals(t, d.ResetIn, time.Second)

	// Refund 10 requests.
	d, err = l.Refund(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroFive, 10)
	test.AssertNotError(t, err, "should not error")
	test.AssertEquals(t, d.Remaining, int64(10))

	// Spend 10 requests, this should succeed.
	d, err = l.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroFive, 10)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(0))
	test.AssertEquals(t, d.ResetIn, time.Second)

	err = l.Reset(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroFive)
	test.AssertNotError(t, err, "should not error")

	// Attempt to spend 20 more requests, this should succeed.
	d, err = l.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroFive, 20)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(0))
	test.AssertEquals(t, d.ResetIn, time.Second)

	// Reset to full.
	clk.Add(d.ResetIn)

	// Refund 1 requests above our limit, this should fail.
	d, err = l.Refund(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroFive, 1)
	test.AssertErrorIs(t, err, ErrBucketAlreadyFull)
	test.AssertEquals(t, d.Remaining, int64(20))
}

func Test_Redis_Limiter_Check_Spend_parity(t *testing.T) {
	t.Parallel()
	il, _, reset := newRedisTestLimiter(t)
	jl, _, _ := newRedisTestLimiter(t)
	defer reset(NewRegistrationsPerIPAddress, tenZeroZeroSix)

	i, err := il.Check(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroSix, 1)
	test.AssertNotError(t, err, "should not error")

	j, err := jl.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroSix, 1)
	test.AssertNotError(t, err, "should not error")
	test.AssertDeepEquals(t, i.Remaining, j.Remaining)
}

func Test_Redis_Limiter_with_new_clients(t *testing.T) {
	t.Parallel()
	l, _, reset := newRedisTestLimiter(t)
	defer reset(NewRegistrationsPerIPAddress, tenZeroZeroSeven)

	// A new client, spend 1 and check our remaining.
	d, err := l.Spend(context.Background(), NewRegistrationsPerIPAddress, tenZeroZeroSeven, 1)
	test.AssertNotError(t, err, "should not error")
	test.Assert(t, d.Allowed, "should be allowed")
	test.AssertEquals(t, d.Remaining, int64(19))
	test.AssertEquals(t, d.RetryIn, time.Duration(0))

	// 1 second == 1000 milliseconds and 1000/20 = 50 milliseconds per request.
	test.AssertEquals(t, d.ResetIn, time.Millisecond*50)
}
