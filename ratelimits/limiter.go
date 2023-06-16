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

type Limiter struct {
	// limits is a map of each limit, identified by name.
	limits limits

	// overrides is a map of each override limit, identified by name:id.
	overrides limits
	source    source
	clk       clock.Clock
}

func NewLimiter(source source, limitsPath, overridesPath string, clk clock.Clock) (*Limiter, error) {
	limiter := &Limiter{source: source, clk: clk}

	defaults, err := loadLimits(limitsPath)
	if err != nil {
		return nil, err
	}
	limiter.limits = defaults

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
	// Allowed is true if the bucket has/had the capacity to allow the request.
	Allowed bool

	// Remaining is the number of requests remaining in the bucket.
	Remaining int

	// RetryIn is the duration the client must wait before they're allowed to
	// make a request.
	RetryIn time.Duration

	// ResetIn is the duration the client would need to wait before the bucket
	// reaches it's maximum capacity.
	ResetIn time.Duration

	// nextTAT is the Theoretical Arrival Time of the next possible request.
	nextTAT time.Time
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

	tat, err := l.source.Get(name, id)
	if err != nil {
		if err == ErrBucketNotFound {
			// First request from this client.
			return l.Initialize(name, id, cost)
		}
		return nil, err
	}
	return decide(l.clk, limit, tat, int64(cost)), nil
}

// MaybeSpend returns a decision indicating whether the request was allowed. If
// so, the cost of the request is spent, otherwise 0 cost is spent.
func (l *Limiter) MaybeSpend(name Name, id string, cost int) (*Decision, error) {
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
	return d, l.source.Set(name, id, d.nextTAT)

}

// Initialize creates a new bucket, specified by name and id, with the cost of
// the request factored into the initial state.
func (l *Limiter) Initialize(name Name, id string, cost int) (*Decision, error) {
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
	d := decide(l.clk, limit, l.clk.Now(), int64(cost))
	return d, l.source.Set(name, id, d.nextTAT)

}

// Refund refunds the cost to the bucket specified.
func (l *Limiter) Refund(name Name, id string, cost int) error {
	if cost <= 0 {
		return ErrInvalidCost
	}

	limit, err := l.getLimit(name, id)
	if err != nil {
		return err
	}

	tat, err := l.source.Get(name, id)
	if err != nil {
		return err
	}
	nextTAT := maybeRefund(l.clk, limit, tat, int64(cost))
	return l.source.Set(name, id, nextTAT)
}

// Reset resets the specified bucket.
func (l *Limiter) Reset(name Name, id string) error {
	return l.source.Delete(name, id)
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
	dl, ok := l.limits[nameToIntString(name)]
	if ok {
		return dl, nil
	}
	return rateLimit{}, fmt.Errorf("limit %q does not exist", name)
}
