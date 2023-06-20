package ratelimits

import (
	"math"
	"time"

	"github.com/jmhodges/clock"
)

// divThenRound divides two int64s and rounds the result to the nearest integer.
// This is used to calculate request intervals and costs in nanoseconds.
func divThenRound(x, y int64) int64 {
	return int64(math.Round(float64(x) / float64(y)))
}

// maybeSpend uses the GCRA algorithm to decide whether to allow a request. It
// returns a Decision struct with the result of the decision and the updated
// TAT. The cost must be 0 or greater and <= the burst capacity of the limit.
func maybeSpend(clk clock.Clock, limit rateLimit, tat time.Time, cost int64) *Decision {
	nowUnix := clk.Now().UnixNano()
	tatUnix := tat.UnixNano()

	// If the TAT is in the future, use it as the starting point for the
	// calculation. Otherwise, use the current time. This is to prevent the
	// bucket from being filled with capacity from the past.
	if nowUnix > tatUnix {
		tatUnix = nowUnix
	}

	// Compute the cost increment.
	emissionInterval := divThenRound(limit.Period.Nanoseconds(), limit.Count)
	costIncrement := emissionInterval * cost

	// Deduct the cost to find the new TAT and residual capacity.
	newTAT := tatUnix + costIncrement
	burstOffset := emissionInterval * limit.Burst
	difference := nowUnix - (newTAT - burstOffset)
	residual := divThenRound(difference, emissionInterval)

	if costIncrement <= 0 && residual == 0 {
		// Edge case: no cost to consume and no capacity to consume it from.
		return &Decision{
			Allowed:   false,
			Remaining: 0,
			RetryIn:   time.Duration(emissionInterval),
			ResetIn:   time.Duration(tatUnix - nowUnix),
			newTAT:    time.Unix(0, tatUnix).UTC(),
		}
	}

	if residual < 0 {
		// Too little capacity to satisfy the cost, deny the request.
		remaining := divThenRound(nowUnix-(tatUnix-burstOffset), emissionInterval)
		return &Decision{
			Allowed:   false,
			Remaining: int(remaining),
			RetryIn:   -time.Duration(difference),
			ResetIn:   time.Duration(tatUnix - nowUnix),
			newTAT:    time.Unix(0, tatUnix).UTC(),
		}
	}

	// There is enough capacity to satisfy the cost, allow the request.
	var retryIn time.Duration
	if residual == 0 {
		// This request will empty the bucket.
		retryIn = time.Duration(emissionInterval)
	}
	return &Decision{
		Allowed:   true,
		Remaining: int(residual),
		RetryIn:   retryIn,
		ResetIn:   time.Duration(newTAT - nowUnix),
		newTAT:    time.Unix(0, newTAT).UTC(),
	}
}

// maybeRefund uses the Generic Cell Rate Algorithm (GCRA) to attempt to refund
// the cost of a request which was previously spent. The refund cost must be 0
// or greater. A cost will only be refunded up to the burst capacity of the
// limit. A partial refund is still considered successful.
func maybeRefund(clk clock.Clock, limit rateLimit, tat time.Time, cost int64) *Decision {
	nowUnix := clk.Now().UnixNano()
	tatUnix := tat.UnixNano()

	// If the TAT is in the past, use the current time as the starting point.
	if nowUnix > tatUnix {
		tatUnix = nowUnix
	}

	// Compute the refund increment.
	emissionInterval := divThenRound(limit.Period.Nanoseconds(), limit.Count)
	refundIncrement := emissionInterval * cost

	// Subtract the refund increment from the TAT to find the new TAT.
	newTAT := tatUnix - refundIncrement

	// Ensure the new TAT is not earlier than now.
	if newTAT < nowUnix {
		newTAT = nowUnix
	}

	// Calculate the new capacity.
	burstOffset := emissionInterval * limit.Burst
	difference := nowUnix - (newTAT - burstOffset)
	residual := divThenRound(difference, emissionInterval)

	return &Decision{
		Allowed:   (newTAT != tatUnix),
		Remaining: int(residual),
		RetryIn:   time.Duration(0),
		ResetIn:   time.Duration(newTAT - nowUnix),
		newTAT:    time.Unix(0, newTAT).UTC(),
	}
}
