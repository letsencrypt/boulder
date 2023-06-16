package ratelimits

import (
	"math"
	"time"

	"github.com/jmhodges/clock"
)

// maybeSpend implements the Generic Cell Rate Algorithm (GCRA). It returns a
// decision indicating whether the request is allowed or denied. The decision
// will always include the new theoretical arrival time (TAT) of the next
// possible request, the number of requests remaining in the bucket, the
// duration the client must wait before they're allowed to make another request,
// and the duration the client would need top wait before the bucket resets
// (reaches max capacity). The cost must be 0 or greater and cannot exceed the
// burst capacity of the bucket.
func maybeSpend(clk clock.Clock, limit RateLimit, tat time.Time, cost int64) Decision {
	nowUnix := clk.Now().UnixNano()
	tatUnix := tat.UnixNano()

	// If the TAT is in the future, use it as the starting point for the
	// calculation. Otherwise, use the current time. This is to prevent the
	// bucket from being filled with capacity from the past.
	if nowUnix > tatUnix {
		tatUnix = nowUnix
	}

	// divThenRound divides two int64s and rounds the result to the nearest
	// integer. This is used to calculate request intervals and costs in
	// nanoseconds.
	divThenRound := func(x, y int64) int64 {
		return int64(math.Round(float64(x) / float64(y)))
	}

	// Compute the total cost.
	emissionInterval := divThenRound(limit.Period.Nanoseconds(), limit.Count)
	costIncrement := emissionInterval * cost

	// Deduct the cost to find the next TAT and residual capacity.
	nextTAT := tatUnix + costIncrement
	burstOffset := emissionInterval * limit.Burst
	difference := nowUnix - (nextTAT - burstOffset)
	residual := divThenRound(difference, emissionInterval)

	if costIncrement <= 0 && residual == 0 {
		// Edge case: no cost to consume and no capacity to consume it from.
		return Decision{
			Allowed:   false,
			Remaining: 0,
			RetryIn:   time.Duration(emissionInterval),
			ResetIn:   time.Duration(tatUnix - nowUnix),
			TAT:       time.Unix(0, tatUnix).UTC(),
		}
	}

	if residual < 0 {
		// Too little capacity to satisfy the cost, deny the request.
		remaining := divThenRound(nowUnix-(tatUnix-burstOffset), emissionInterval)
		return Decision{
			Allowed:   false,
			Remaining: int(remaining),
			RetryIn:   -time.Duration(difference),
			ResetIn:   time.Duration(tatUnix - nowUnix),
			TAT:       time.Unix(0, tatUnix).UTC(),
		}
	}

	// There is enough capacity to satisfy the cost, allow the request.
	var retryIn time.Duration
	if residual == 0 {
		// This request will empty the bucket.
		retryIn = time.Duration(emissionInterval)
	}
	return Decision{
		Allowed:   true,
		Remaining: int(residual),
		RetryIn:   retryIn,
		ResetIn:   time.Duration(nextTAT - nowUnix),
		TAT:       time.Unix(0, nextTAT).UTC(),
	}
}
