package ratelimits

import (
	"fmt"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/config"
)

// ErrInvalidCostForCheck is returned when a cost is less than zero.
var ErrInvalidCostForCheck = fmt.Errorf("cost must be greater than zero")

// ErrInvalidCostForSpend is returned when a cost is less than or equal to zero.
var ErrInvalidCostForSpend = fmt.Errorf("cost must be greater than zero")

// ErrInvalidCostForLimit is returned when the specified cost is greater than
// the limit's possible maximum capacity.
var ErrInvalidCostForLimit = fmt.Errorf("cost must be less than or equal to the limit's burst")

// RateLimit specifies the frequency of requests allowed from a client over a
// period of time. All fields are required and MUST be greater than zero.
type RateLimit struct {
	// Burst specifies maximum concurrent (allowed) requests at any given time.
	// It MUST be greater than zero.
	Burst int64

	// Count is the number of requests allowed per period duration. It MUST be
	// greater than zero.
	Count int64

	// Period is the duration of time in which the count (of requests) is
	// allowed. It MUST be greater than zero.
	Period config.Duration
}

type Limiter struct {
	// limits is a map of each limit, identified by 'prefix' to a default limit
	// for that prefix.
	limits limits

	// overrides is a map of each limit override, identified by 'prefix:id' to
	// an override limit for that prefix.
	overrides limits
	source    source
	clk       clock.Clock
}

func NewLimiter(limitsPath, overridesPath string, clk clock.Clock) (*Limiter, error) {
	limiter := &Limiter{source: newInmem(), clk: clk}

	defaults, err := loadLimits(limitsPath)
	if err != nil {
		return nil, err
	}
	limiter.limits = defaults

	if overridesPath == "" {
		// No overrides file.
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
	// Allowed if the cost was consumed from the bucket.
	Allowed bool

	// Remaining is the number of requests remaining in the bucket.
	Remaining int

	// RetryIn is the duration the client SHOULD wait before they're allowed to
	// make another request.
	RetryIn time.Duration

	// ResetIn is the duration the client would need to wait before the bucket
	// reaches maximum (burst) capacity of requests.
	ResetIn time.Duration

	// TAT is the Theoretical Arrival Time of the next possible request.
	TAT time.Time
}

func (l *Limiter) Check(prefix Prefix, id string, cost int) (Decision, error) {
	if cost < 0 {
		return Decision{}, ErrInvalidCostForCheck
	}

	limit, err := l.getLimit(prefix, id)
	if err != nil {
		return Decision{}, err
	}

	if int64(cost) > limit.Burst {
		return Decision{}, ErrInvalidCostForLimit
	}

	tat, err := l.source.Get(prefix, id)
	if err != nil {
		return Decision{}, err
	}
	return maybeSpend(l.clk, limit, tat, int64(cost)), nil
}

func (l *Limiter) Spend(prefix Prefix, id string, cost int) (Decision, error) {
	if cost <= 0 {
		return Decision{}, ErrInvalidCostForSpend
	}
	d, err := l.Check(prefix, id, cost)
	if err != nil {
		return Decision{}, err
	}
	if d.Allowed {
		l.source.Set(prefix, id, d.TAT)
	}
	return d, nil

}

func (l *Limiter) Refund(prefix, id string, cost int) error {
	return nil
}

func (l *Limiter) Reset(prefix, id string) error {
	return nil
}

// GetLimit returns the default limit, unless an override limit has defined for
// the client. Prefix is the limit type, and id is the client identifier. Prefix
// MUST be a valid limit type but id is optional.
func (l *Limiter) getLimit(prefix Prefix, id string) (RateLimit, error) {
	if id != "" {
		// Check for override.
		ol, ok := l.overrides[overrideKey(prefix, id)]
		if ok {
			return ol, nil
		}
	}
	dl, ok := l.limits[prefixToIntString(prefix)]
	if ok {
		return dl, nil
	}
	return RateLimit{}, fmt.Errorf("limit %q does not exist", prefix)
}
