package ratelimits

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"

	berrors "github.com/letsencrypt/boulder/errors"
)

const (
	// Allowed is used for rate limit metrics, it's the value of the 'decision'
	// label when a request was allowed.
	Allowed = "allowed"

	// Denied is used for rate limit metrics, it's the value of the 'decision'
	// label when a request was denied.
	Denied = "denied"
)

// allowedDecision is an "allowed" *Decision that should be returned when a
// checked limit is found to be disabled.
var allowedDecision = &Decision{allowed: true, remaining: math.MaxInt64}

// Limiter provides a high-level interface for rate limiting requests by
// utilizing a leaky bucket-style approach.
type Limiter struct {
	// source is used to store buckets. It must be safe for concurrent use.
	source source
	clk    clock.Clock

	spendLatency       *prometheus.HistogramVec
	overrideUsageGauge *prometheus.GaugeVec
}

// NewLimiter returns a new *Limiter. The provided source must be safe for
// concurrent use.
func NewLimiter(clk clock.Clock, source source, stats prometheus.Registerer) (*Limiter, error) {
	spendLatency := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "ratelimits_spend_latency",
		Help: fmt.Sprintf("Latency of ratelimit checks labeled by limit=[name] and decision=[%s|%s], in seconds", Allowed, Denied),
		// Exponential buckets ranging from 0.0005s to 3s.
		Buckets: prometheus.ExponentialBuckets(0.0005, 3, 8),
	}, []string{"limit", "decision"})
	stats.MustRegister(spendLatency)

	overrideUsageGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ratelimits_override_usage",
		Help: "Proportion of override limit used, by limit name and bucket key.",
	}, []string{"limit", "bucket_key"})
	stats.MustRegister(overrideUsageGauge)

	return &Limiter{
		source:             source,
		clk:                clk,
		spendLatency:       spendLatency,
		overrideUsageGauge: overrideUsageGauge,
	}, nil
}

// Decision represents the result of a rate limit check or spend operation. To
// check the result of a *Decision, call the Result() method.
type Decision struct {
	// allowed is true if the bucket possessed enough capacity to allow the
	// request given the cost.
	allowed bool

	// remaining is the number of requests the client is allowed to make before
	// they're rate limited.
	remaining int64

	// retryIn is the duration the client MUST wait before they're allowed to
	// make a request.
	retryIn time.Duration

	// resetIn is the duration the bucket will take to refill to its maximum
	// capacity, assuming no further requests are made.
	resetIn time.Duration

	// newTAT indicates the time at which the bucket will be full. It is the
	// theoretical arrival time (TAT) of next request. It must be no more than
	// (burst * (period / count)) in the future at any single point in time.
	newTAT time.Time

	// transaction is the Transaction that resulted in this Decision. It is
	// included for the production of verbose Subscriber-facing errors. It is
	// set by the Limiter before returning the Decision.
	transaction Transaction
}

// Result translates a denied *Decision into a berrors.RateLimitError for the
// Subscriber, or returns nil if the *Decision allows the request. The error
// message includes a human-readable description of the exceeded rate limit and
// a retry-after timestamp.
func (d *Decision) Result(now time.Time) error {
	if d.allowed {
		return nil
	}

	fmt.Printf("\n\n%#v\n\n", d.transaction)

	// Add 0-3% jitter to the RetryIn duration to prevent thundering herd.
	jitter := time.Duration(float64(d.retryIn) * 0.03 * rand.Float64())
	retryAfter := d.retryIn + jitter
	retryAfterTs := now.UTC().Add(retryAfter).Format("2006-01-02 15:04:05 MST")

	switch d.transaction.limit.name {
	case NewRegistrationsPerIPAddress:
		return berrors.RegistrationsPerIPError(
			retryAfter,
			"too many new registrations (%d) from this IP address in the last %s, retry after %s",
			d.transaction.limit.Burst,
			d.transaction.limit.Period.Duration,
			retryAfterTs,
		)

	case NewRegistrationsPerIPv6Range:
		return berrors.RateLimitError(
			retryAfter,
			"too many new registrations (%d) from this /48 block of IPv6 addresses in the last %s, retry after %s",
			d.transaction.limit.Burst,
			d.transaction.limit.Period.Duration,
			retryAfterTs,
		)
	case NewOrdersPerAccount:
		return berrors.RateLimitError(
			retryAfter,
			"too many new orders (%d) from this account in the last %s, retry after %s",
			d.transaction.limit.Burst,
			d.transaction.limit.Period.Duration,
			retryAfterTs,
		)

	case FailedAuthorizationsPerDomainPerAccount:
		// Uses bucket key 'enum:regId:domain'.
		idx := strings.LastIndex(d.transaction.bucketKey, ":")
		if idx == -1 {
			return berrors.InternalServerError("unrecognized bucket key while generating error")
		}
		domain := d.transaction.bucketKey[idx+1:]
		return berrors.FailedValidationError(
			retryAfter,
			"too many failed authorizations (%d) for %q in the last %s, retry after %s",
			d.transaction.limit.Burst,
			domain,
			d.transaction.limit.Period.Duration,
			retryAfterTs,
		)

	case CertificatesPerDomain, CertificatesPerDomainPerAccount:
		// Uses bucket key 'enum:domain' or 'enum:regId:domain' respectively.
		idx := strings.LastIndex(d.transaction.bucketKey, ":")
		if idx == -1 {
			return berrors.InternalServerError("unrecognized bucket key while generating error")
		}
		domain := d.transaction.bucketKey[idx+1:]
		return berrors.RateLimitError(
			retryAfter,
			"too many certificates (%d) already issued for %q in the last %s, retry after %s",
			d.transaction.limit.Burst,
			domain,
			d.transaction.limit.Period.Duration,
			retryAfterTs,
		)

	case CertificatesPerFQDNSet:
		return berrors.DuplicateCertificateError(
			retryAfter,
			"too many certificates (%d) already issued for this exact set of domains in the last %s, retry after %s",
			d.transaction.limit.Burst,
			d.transaction.limit.Period.Duration,
			retryAfterTs,
		)

	default:
		return berrors.InternalServerError("cannot generate error for unknown rate limit")
	}
}

// Check DOES NOT deduct the cost of the request from the provided bucket's
// capacity. The returned *Decision indicates whether the capacity exists to
// satisfy the cost and represents the hypothetical state of the bucket IF the
// cost WERE to be deducted. If no bucket exists it will NOT be created. No
// state is persisted to the underlying datastore.
func (l *Limiter) Check(ctx context.Context, txn Transaction) (*Decision, error) {
	if txn.allowOnly() {
		return allowedDecision, nil
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
		return maybeSpend(l.clk, txn, l.clk.Now()), nil
	}
	return maybeSpend(l.clk, txn, tat), nil
}

// Spend attempts to deduct the cost from the provided bucket's capacity. The
// returned *Decision indicates whether the capacity existed to satisfy the cost
// and represents the current state of the bucket. If no bucket exists it WILL
// be created WITH the cost factored into its initial state. The new bucket
// state is persisted to the underlying datastore, if applicable, before
// returning.
func (l *Limiter) Spend(ctx context.Context, txn Transaction) (*Decision, error) {
	return l.BatchSpend(ctx, []Transaction{txn})
}

func prepareBatch(txns []Transaction) ([]Transaction, []string, error) {
	var bucketKeys []string
	var transactions []Transaction
	for _, txn := range txns {
		if txn.allowOnly() {
			// Ignore allow-only transactions.
			continue
		}
		if slices.Contains(bucketKeys, txn.bucketKey) {
			return nil, nil, fmt.Errorf("found duplicate bucket %q in batch", txn.bucketKey)
		}
		bucketKeys = append(bucketKeys, txn.bucketKey)
		transactions = append(transactions, txn)
	}
	return transactions, bucketKeys, nil
}

type batchDecision struct {
	*Decision
}

func newBatchDecision() *batchDecision {
	return &batchDecision{
		Decision: &Decision{
			allowed:   true,
			remaining: math.MaxInt64,
		},
	}
}

func (d *batchDecision) merge(in *Decision) {
	d.allowed = d.allowed && in.allowed
	d.remaining = min(d.remaining, in.remaining)
	d.resetIn = max(d.resetIn, in.resetIn)
	if in.newTAT.After(d.newTAT) {
		d.newTAT = in.newTAT
		d.retryIn = in.retryIn
		d.transaction = in.transaction
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
	start := l.clk.Now()

	batch, bucketKeys, err := prepareBatch(txns)
	if err != nil {
		return nil, err
	}
	if len(batch) == 0 {
		// All Transactions were allow-only.
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
	txnOutcomes := make(map[Transaction]string)

	for _, txn := range batch {
		tat, exists := tats[txn.bucketKey]
		if !exists {
			// First request from this client.
			tat = l.clk.Now()
		}

		d := maybeSpend(l.clk, txn, tat)

		if txn.limit.isOverride() {
			utilization := float64(txn.limit.Burst-d.remaining) / float64(txn.limit.Burst)
			l.overrideUsageGauge.WithLabelValues(txn.limit.name.String(), txn.limit.overrideKey).Set(utilization)
		}

		if d.allowed && (tat != d.newTAT) && txn.spend {
			// New bucket state should be persisted.
			newTATs[txn.bucketKey] = d.newTAT
		}

		if !txn.spendOnly() {
			batchDecision.merge(d)
		}

		txnOutcomes[txn] = Denied
		if d.allowed {
			txnOutcomes[txn] = Allowed
		}
	}

	if batchDecision.allowed && len(newTATs) > 0 {
		err = l.source.BatchSet(ctx, newTATs)
		if err != nil {
			return nil, err
		}
	}

	// Observe latency equally across all transactions in the batch.
	totalLatency := l.clk.Since(start)
	perTxnLatency := totalLatency / time.Duration(len(txnOutcomes))
	for txn, outcome := range txnOutcomes {
		l.spendLatency.WithLabelValues(txn.limit.name.String(), outcome).Observe(perTxnLatency.Seconds())
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
	return l.BatchRefund(ctx, []Transaction{txn})
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
	batch, bucketKeys, err := prepareBatch(txns)
	if err != nil {
		return nil, err
	}
	if len(batch) == 0 {
		// All Transactions were allow-only.
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

		if txn.checkOnly() {
			// The cost of check-only transactions are never refunded.
			txn.cost = 0
		}
		d := maybeRefund(l.clk, txn, tat)
		batchDecision.merge(d)
		if d.allowed && tat != d.newTAT {
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
func (l *Limiter) Reset(ctx context.Context, bucketKey string) error {
	// Remove cancellation from the request context so that transactions are not
	// interrupted by a client disconnect.
	ctx = context.WithoutCancel(ctx)
	return l.source.Delete(ctx, bucketKey)
}
