package ratelimits

import (
	"fmt"
	"time"

	"github.com/jmhodges/clock"
)

// ErrInvalidCost indicates that the cost specified was <= 0.
var ErrInvalidCost = fmt.Errorf("invalid cost, must be > 0")

// ErrInvalidCostForCheck indicates that the check cost specified was < 0.
var ErrInvalidCostForCheck = fmt.Errorf("invalid check cost, must be >= 0")

// ErrInvalidCostOverLimit indicates that the cost specified was > limit.Burst.
var ErrInvalidCostOverLimit = fmt.Errorf("invalid cost, must be <= limit.Burst")

var ErrBucketAlreadyFull = fmt.Errorf("bucket already full")

type Limiter struct {
	// defaults stores default limits by 'name'.
	defaults limits

	// overrides stores override limits by 'name:id'.
	overrides limits
	source    source
	clk       clock.Clock
}

func NewLimiter(clk clock.Clock, source source, limitsPath, overridesPath string) (*Limiter, error) {
	limiter := &Limiter{source: source, clk: clk}

	defaults, err := loadLimits(limitsPath)
	if err != nil {
		return nil, err
	}
	limiter.defaults = defaults

	if overridesPath == "" {
		// No overrides specified.
		limiter.overrides = make(limits)
		return limiter, nil
	}

	overrides, err := loadLimits(overridesPath)
	if err != nil {
		return nil, err
	}
	limiter.overrides = overrides

	return limiter, nil
}

type Decision struct {
	// Allowed is true if the bucket has the capacity to allow the request.
	Allowed bool

	// Remaining is the number of requests remaining in the bucket.
	Remaining int

	// RetryIn is the duration the client must wait before they're allowed to
	// make a request.
	RetryIn time.Duration

	// ResetIn is the duration the client would need to wait before the bucket
	// reaches it's maximum capacity.
	ResetIn time.Duration

	// newTAT is the Theoretical Arrival Time of the next possible request.
	newTAT time.Time
}

// Check returns a decision indicating whether the request will be allowed but
// does not spend the cost of the request. Most callers should use MaybeSpend.
func (l *Limiter) Check(name Name, id string, cost int) (*Decision, error) {
	if cost < 0 {
		return nil, ErrInvalidCostForCheck
	}

	limit, err := l.getLimit(name, id)
	if err != nil {
		return nil, err
	}

	if int64(cost) > limit.Burst {
		return nil, ErrInvalidCostOverLimit
	}

	tat, err := l.source.Get(bucketKey(name, id))
	if err != nil {
		if err == ErrBucketNotFound {
			// First request from this client.
			return l.initialize(limit, name, id, cost)
		}
		return nil, err
	}
	return maybeSpend(l.clk, limit, tat, int64(cost)), nil
}

// Spend returns a decision indicating whether the request was allowed. If so,
// the cost of the request is spent, otherwise 0 cost is spent. The Decision
// returned will always include the number of requests remaining in the bucket,
// the duration the client must wait before they're allowed to make another
// request, and the duration the client should wait before the bucket reaches
// max capacity (resets).
func (l *Limiter) Spend(name Name, id string, cost int) (*Decision, error) {
	if cost <= 0 {
		return nil, ErrInvalidCost
	}

	d, err := l.Check(name, id, cost)
	if err != nil {
		return nil, err
	}

	if !d.Allowed {
		return d, nil
	}
	return d, l.source.Set(bucketKey(name, id), d.newTAT)

}

// Refund returns a decision indicating whether the refund was possible. If so,
// the cost of the request is refunded, otherwise 0 cost is refunded. Refunds
// are never allowed to exceed the capacity of the bucket. Partial refunds are
// still considered successful (e.g. if the bucket has a capacity of 10 and
// there are 5 requests remaining, a refund of 7 will be successful and the
// bucket will have 10 requests remaining).
func (l *Limiter) Refund(name Name, id string, cost int) (*Decision, error) {
	if cost <= 0 {
		return nil, ErrInvalidCost
	}

	limit, err := l.getLimit(name, id)
	if err != nil {
		return nil, err
	}

	tat, err := l.source.Get(bucketKey(name, id))
	if err != nil {
		return nil, err
	}
	d := maybeRefund(l.clk, limit, tat, int64(cost))
	if !d.Allowed {
		return d, ErrBucketAlreadyFull
	}
	return d, l.source.Set(bucketKey(name, id), d.newTAT)

}

// Reset resets the specified bucket.
func (l *Limiter) Reset(name Name, id string) error {
	return l.source.Delete(bucketKey(name, id))
}

// initialize creates a new bucket, specified by name and id, with the cost of
// the request factored into the initial state.
func (l *Limiter) initialize(limit rateLimit, name Name, id string, cost int) (*Decision, error) {
	d := maybeSpend(l.clk, limit, l.clk.Now(), int64(cost))
	return d, l.source.Set(bucketKey(name, id), d.newTAT)

}

// GetLimit returns the limit for the specified by name and id, name is
// required, id is optional. If id is left unspecified, the default limit for
// the limit specified by name is returned.
func (l *Limiter) getLimit(name Name, id string) (rateLimit, error) {
	if id != "" {
		// Check for override.
		ol, ok := l.overrides[overrideKey(name, id)]
		if ok {
			return ol, nil
		}
	}
	dl, ok := l.defaults[nameToIntString(name)]
	if ok {
		return dl, nil
	}
	return rateLimit{}, fmt.Errorf("limit %q does not exist", name)
}
