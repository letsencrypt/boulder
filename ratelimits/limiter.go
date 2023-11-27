package ratelimits

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// Allowed is used for rate limit metrics, it's the value of the 'decision'
	// label when a request was allowed.
	Allowed = "allowed"

	// Denied is used for rate limit metrics, it's the value of the 'decision'
	// label when a request was denied.
	Denied = "denied"
)

// ErrInvalidCost indicates that the cost specified was < 0.
var ErrInvalidCost = fmt.Errorf("invalid cost, must be >= 0")

// ErrInvalidCostOverLimit indicates that the cost specified was > limit.Burst.
var ErrInvalidCostOverLimit = fmt.Errorf("invalid cost, must be <= limit.Burst")

// errLimitDisabled indicates that the limit name specified is valid but is not
// currently configured.
var errLimitDisabled = errors.New("limit disabled")

// allowedDecision is an "allowed" *Decision that should be returned when a
// checked limit is found to be disabled.
var allowedDecision = &Decision{Allowed: true, Remaining: math.MaxInt64}

// Limiter provides a high-level interface for rate limiting requests by
// utilizing a leaky bucket-style approach.
type Limiter struct {
	// defaults stores default limits by 'name'.
	defaults limits

	// overrides stores override limits by 'name:id'.
	overrides limits

	// source is used to store buckets. It must be safe for concurrent use.
	source source
	clk    clock.Clock

	spendLatency       *prometheus.HistogramVec
	overrideUsageGauge *prometheus.GaugeVec
}

// NewLimiter returns a new *Limiter. The provided source must be safe for
// concurrent use. The defaults and overrides paths are expected to be paths to
// YAML files that contain the default and override limits, respectively. The
// overrides file is optional, all other arguments are required.
func NewLimiter(clk clock.Clock, source source, defaults, overrides string, stats prometheus.Registerer) (*Limiter, error) {
	limiter := &Limiter{source: source, clk: clk}

	var err error
	limiter.defaults, err = loadAndParseDefaultLimits(defaults)
	if err != nil {
		return nil, err
	}

	limiter.spendLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "ratelimits_spend_latency",
		Help: fmt.Sprintf("Latency of ratelimit checks labeled by limit=[name] and decision=[%s|%s], in seconds", Allowed, Denied),
		// Exponential buckets ranging from 0.0005s to 3s.
		Buckets: prometheus.ExponentialBuckets(0.0005, 3, 8),
	}, []string{"limit", "decision"})
	stats.MustRegister(limiter.spendLatency)

	if overrides == "" {
		// No overrides specified, initialize an empty map.
		limiter.overrides = make(limits)
		return limiter, nil
	}

	limiter.overrides, err = loadAndParseOverrideLimits(overrides)
	if err != nil {
		return nil, err
	}

	limiter.overrideUsageGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ratelimits_override_usage",
		Help: "Proportion of override limit used, by limit name and bucket key.",
	}, []string{"limit", "bucket_key"})
	stats.MustRegister(limiter.overrideUsageGauge)

	return limiter, nil
}

type Decision struct {
	// Allowed is true if the bucket possessed enough capacity to allow the
	// request given the cost.
	Allowed bool

	// Remaining is the number of requests the client is allowed to make before
	// they're rate limited.
	Remaining int64

	// RetryIn is the duration the client MUST wait before they're allowed to
	// make a request.
	RetryIn time.Duration

	// ResetIn is the duration the bucket will take to refill to its maximum
	// capacity, assuming no further requests are made.
	ResetIn time.Duration

	// newTAT indicates the time at which the bucket will be full. It is the
	// theoretical arrival time (TAT) of next request. It must be no more than
	// (burst * (period / count)) in the future at any single point in time.
	newTAT time.Time
}

// Check DOES NOT deduct the cost of the request from the provided bucket's
// capacity. The returned *Decision indicates whether the capacity exists to
// satisfy the cost and represents the hypothetical state of the bucket IF the
// cost WERE to be deducted. If no bucket exists it will NOT be created. No
// state is persisted to the underlying datastore.
func (l *Limiter) Check(ctx context.Context, txn Transaction) (*Decision, error) {
	if txn.cost < 0 {
		return nil, ErrInvalidCost
	}

	limit, err := l.getLimit(txn.limitName, txn.bucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return allowedDecision, nil
		}
		return nil, err
	}

	if txn.cost > limit.Burst {
		return nil, ErrInvalidCostOverLimit
	}

	// Remove cancellation from the request context so that transactions are not
	// interrupted by a client disconnect.
	ctx = context.WithoutCancel(ctx)
	tat, err := l.source.Get(ctx, txn.bucketKey)
	if err != nil {
		if !errors.Is(err, ErrBucketNotFound) {
			return nil, err
		}
		// First request from this client. No need to initialize the bucket
		// because this is a check, not a spend. A TAT of "now" is equivalent to
		// a full bucket.
		return maybeSpend(l.clk, limit, l.clk.Now(), txn.cost), nil
	}
	return maybeSpend(l.clk, limit, tat, txn.cost), nil
}

// Spend attempts to deduct the cost from the provided bucket's capacity. The
// returned *Decision indicates whether the capacity existed to satisfy the cost
// and represents the current state of the bucket. If no bucket exists it WILL
// be created WITH the cost factored into its initial state. The new bucket
// state is persisted to the underlying datastore, if applicable, before
// returning.
func (l *Limiter) Spend(ctx context.Context, txn Transaction) (*Decision, error) {
	if txn.cost < 0 {
		return nil, ErrInvalidCost
	}

	limit, err := l.getLimit(txn.limitName, txn.bucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return allowedDecision, nil
		}
		return nil, err
	}

	if txn.cost > limit.Burst {
		return nil, ErrInvalidCostOverLimit
	}

	start := l.clk.Now()
	status := Denied
	defer func() {
		l.spendLatency.WithLabelValues(txn.limitName.String(), status).Observe(l.clk.Since(start).Seconds())
	}()

	// Remove cancellation from the request context so that transactions are not
	// interrupted by a client disconnect.
	ctx = context.WithoutCancel(ctx)
	tat, err := l.source.Get(ctx, txn.bucketKey)
	if err != nil {
		if errors.Is(err, ErrBucketNotFound) {
			// First request from this client.
			d, err := l.initialize(ctx, limit, txn)
			if err != nil {
				return nil, err
			}
			if d.Allowed {
				status = Allowed
			}
			return d, nil
		}
		return nil, err
	}

	d := maybeSpend(l.clk, limit, tat, txn.cost)

	if limit.isOverride {
		// Calculate the current utilization of the override limit.
		utilization := float64(limit.Burst-d.Remaining) / float64(limit.Burst)
		l.overrideUsageGauge.WithLabelValues(txn.limitName.String(), txn.bucketKey).Set(utilization)
	}

	if !d.Allowed {
		if txn.spendOnly() {
			return allowedDecision, nil
		}
		return d, nil
	}

	if tat == d.newTAT || txn.checkOnly() {
		// No-op.
		return d, nil
	}

	err = l.source.Set(ctx, txn.bucketKey, d.newTAT)
	if err != nil {
		return nil, err
	}
	status = Allowed
	return d, nil
}

type batchTransaction struct {
	Transaction
	limit limit
}

func (l *Limiter) prepareBatch(txns []Transaction) ([]batchTransaction, []string, error) {
	var batchTxns []batchTransaction
	var bucketKeys []string
	for _, txn := range txns {
		if txn.cost < 0 {
			return nil, nil, ErrInvalidCost
		}
		limit, err := l.getLimit(txn.limitName, txn.bucketKey)
		if err != nil {
			if errors.Is(err, errLimitDisabled) {
				continue
			}
			return nil, nil, err
		}
		if txn.cost > limit.Burst {
			return nil, nil, ErrInvalidCostOverLimit
		}
		if slices.Contains(bucketKeys, txn.bucketKey) {
			return nil, nil, fmt.Errorf("found duplicate bucket %q in batch", txn.bucketKey)
		}
		bucketKeys = append(bucketKeys, txn.bucketKey)
		batchTxns = append(batchTxns, batchTransaction{txn, limit})
	}
	return batchTxns, bucketKeys, nil
}

type batchDecision struct {
	*Decision
}

func newBatchDecision() *batchDecision {
	return &batchDecision{
		Decision: &Decision{
			Allowed:   true,
			Remaining: math.MaxInt64,
		},
	}
}

func (d *batchDecision) merge(in *Decision) {
	d.Allowed = d.Allowed && in.Allowed
	d.Remaining = min(d.Remaining, in.Remaining)
	d.RetryIn = max(d.RetryIn, in.RetryIn)
	d.ResetIn = max(d.ResetIn, in.ResetIn)
	if in.newTAT.After(d.newTAT) {
		d.newTAT = in.newTAT
	}
}

// BatchSpend attempts to deduct the costs from the provided buckets'
// capacities. If applicable, new bucket states are persisted to the underlying
// datastore before returning. Non-existent buckets will be initialized WITH the
// cost factored into the initial state. The following rules are applied to
// merge the Decisions for each Transaction into a single batch Decision:
//   - Allowed is true if all Transactions where check is true were allowed,
//   - RetryIn and ResetIn are the largest values of each across all Decisions,
//   - Remaining is the smallest value of each across all Decisions, and
//   - Decisions resulting from spend-only Transactions are never merged.
func (l *Limiter) BatchSpend(ctx context.Context, txns []Transaction) (*Decision, error) {
	batch, bucketKeys, err := l.prepareBatch(txns)
	if err != nil {
		return nil, err
	}
	if len(batch) <= 0 {
		// All limits in the batch were disabled.
		return allowedDecision, nil
	}

	// Remove cancellation from the request context so that transactions are not
	// interrupted by a client disconnect.
	ctx = context.WithoutCancel(ctx)
	tats, err := l.source.BatchGet(ctx, bucketKeys)
	if err != nil {
		return nil, err
	}

	start := l.clk.Now()
	batchDecision := newBatchDecision()
	newTATs := make(map[string]time.Time)

	for _, txn := range batch {
		tat, exists := tats[txn.bucketKey]
		if !exists {
			// First request from this client.
			tat = l.clk.Now()
		}

		d := maybeSpend(l.clk, txn.limit, tat, txn.cost)

		if txn.limit.isOverride {
			utilization := float64(txn.limit.Burst-d.Remaining) / float64(txn.limit.Burst)
			l.overrideUsageGauge.WithLabelValues(txn.limitName.String(), txn.bucketKey).Set(utilization)
		}

		if d.Allowed && (tat != d.newTAT) && txn.spend {
			// New bucket state should be persisted.
			newTATs[txn.bucketKey] = d.newTAT
		}

		if txn.spendOnly() {
			d = allowedDecision
		}
		batchDecision.merge(d)
	}

	if batchDecision.Allowed {
		err = l.source.BatchSet(ctx, newTATs)
		if err != nil {
			return nil, err
		}
		l.spendLatency.WithLabelValues("batch", Allowed).Observe(l.clk.Since(start).Seconds())
	} else {
		l.spendLatency.WithLabelValues("batch", Denied).Observe(l.clk.Since(start).Seconds())
	}
	return batchDecision.Decision, nil
}

// Refund attempts to refund all of the cost to the capacity of the specified
// bucket. The returned *Decision indicates whether the refund was successful
// and represents the current state of the bucket. The new bucket state is
// persisted to the underlying datastore, if applicable, before returning. If no
// bucket exists it will NOT be created. Spend-only Transactions are assumed to
// be refundable. Check-only Transactions are never refunded.
//
// Note: The amount refunded cannot cause the bucket to exceed its maximum
// capacity. Partial refunds are allowed and are considered successful. For
// instance, if a bucket has a maximum capacity of 10 and currently has 5
// requests remaining, a refund request of 7 will result in the bucket reaching
// its maximum capacity of 10, not 12.
func (l *Limiter) Refund(ctx context.Context, txn Transaction) (*Decision, error) {
	if txn.cost < 0 {
		return nil, ErrInvalidCost
	}

	limit, err := l.getLimit(txn.limitName, txn.bucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return allowedDecision, nil
		}
		return nil, err
	}

	// Remove cancellation from the request context so that transactions are not
	// interrupted by a client disconnect.
	ctx = context.WithoutCancel(ctx)
	tat, err := l.source.Get(ctx, txn.bucketKey)
	if err != nil {
		return nil, err
	}
	d := maybeRefund(l.clk, limit, tat, txn.cost)
	if tat == d.newTAT || txn.checkOnly() {
		return maybeRefund(l.clk, limit, tat, 0), nil
	}
	if d.Allowed {
		// Persist the new bucket state.
		return d, l.source.Set(ctx, txn.bucketKey, d.newTAT)
	}
	// Bucket is already full.
	return d, nil
}

// BatchRefund attempts to refund all or some of the costs to the provided
// buckets' capacities. Non-existent buckets will NOT be initialized. The new
// bucket state is persisted to the underlying datastore, if applicable, before
// returning. Spend-only Transactions are assumed to be refundable. Check-only
// Transactions are never refunded. The following rules are applied to merge the
// Decisions for each Transaction into a single batch Decision:
//   - Allowed is true if all Transactions where check is true were allowed,
//   - RetryIn and ResetIn are the largest values of each across all Decisions,
//   - Remaining is the smallest value of each across all Decisions, and
//   - Decisions resulting from spend-only Transactions are never merged.
func (l *Limiter) BatchRefund(ctx context.Context, txns []Transaction) (*Decision, error) {
	batch, bucketKeys, err := l.prepareBatch(txns)
	if err != nil {
		return nil, err
	}
	if len(batch) <= 0 {
		// All limits in the batch were disabled.
		return allowedDecision, nil
	}

	// Remove cancellation from the request context so that transactions are not
	// interrupted by a client disconnect.
	ctx = context.WithoutCancel(ctx)
	tats, err := l.source.BatchGet(ctx, bucketKeys)
	if err != nil {
		return nil, err
	}

	batchDecision := newBatchDecision()
	newTATs := make(map[string]time.Time)

	for _, txn := range batch {
		tat, exists := tats[txn.bucketKey]
		if !exists {
			// Ignore non-existent bucket.
			continue
		}

		d := maybeRefund(l.clk, txn.limit, tat, txn.cost)
		if tat == d.newTAT || txn.checkOnly() {
			d = maybeRefund(l.clk, txn.limit, tat, 0)
		}
		batchDecision.merge(d)
		if d.Allowed && (tat != d.newTAT) {
			// New bucket state should be persisted.
			newTATs[txn.bucketKey] = d.newTAT
		}
	}

	if len(newTATs) > 0 {
		err = l.source.BatchSet(ctx, newTATs)
		if err != nil {
			return nil, err
		}
	}
	return batchDecision.Decision, nil
}

// Reset resets the specified bucket to its maximum capacity. The new bucket
// state is persisted to the underlying datastore before returning.
func (l *Limiter) Reset(ctx context.Context, bId bucketId) error {
	// Remove cancellation from the request context so that transactions are not
	// interrupted by a client disconnect.
	ctx = context.WithoutCancel(ctx)
	return l.source.Delete(ctx, bId.bucketKey)
}

// initialize creates a new bucket and sets its TAT to now, which is equivalent
// to a full bucket. The new bucket state is persisted to the underlying
// datastore before returning.
func (l *Limiter) initialize(ctx context.Context, rl limit, txn Transaction) (*Decision, error) {
	d := maybeSpend(l.clk, rl, l.clk.Now(), txn.cost)

	// Remove cancellation from the request context so that transactions are not
	// interrupted by a client disconnect.
	ctx = context.WithoutCancel(ctx)
	err := l.source.Set(ctx, txn.bucketKey, d.newTAT)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// getLimit returns the limit for the specified by name and bucketKey, name is
// required, bucketKey is optional. If bucketkey is left unspecified, the
// default limit for the limit specified by name is returned. If no default
// limit exists for the specified name, errLimitDisabled is returned.
func (l *Limiter) getLimit(name Name, bucketKey string) (limit, error) {
	if !name.isValid() {
		// This should never happen. Callers should only be specifying the limit
		// Name enums defined in this package.
		return limit{}, fmt.Errorf("specified name enum %q, is invalid", name)
	}
	if bucketKey != "" {
		// Check for override.
		ol, ok := l.overrides[bucketKey]
		if ok {
			return ol, nil
		}
	}
	dl, ok := l.defaults[name.EnumString()]
	if ok {
		return dl, nil
	}
	return limit{}, errLimitDisabled
}
