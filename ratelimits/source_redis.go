package ratelimits

import (
	"context"
	"errors"
	"strings"
	"time"

	bredis "github.com/letsencrypt/boulder/redis"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
)

// Compile-time check that RedisSource implements the source interface.
var _ source = (*RedisSource)(nil)

// RedisSource is a ratelimits source backed by sharded Redis.
type RedisSource struct {
	client        *redis.Ring
	timeout       time.Duration
	clk           clock.Clock
	setLatency    *prometheus.HistogramVec
	getLatency    *prometheus.HistogramVec
	deleteLatency *prometheus.HistogramVec
}

// NewRedisSource returns a new Redis backed source using the provided
// *redis.Ring client.
func NewRedisSource(client *redis.Ring, timeout time.Duration, clk clock.Clock, stats prometheus.Registerer) *RedisSource {
	if len(client.Options().Addrs) == 0 {
		return nil
	}
	var addrs []string
	for addr := range client.Options().Addrs {
		addrs = append(addrs, addr)
	}
	labels := prometheus.Labels{
		"addresses": strings.Join(addrs, ", "),
		"user":      client.Options().Username,
	}
	stats.MustRegister(bredis.NewMetricsCollector(client, labels))
	setLatency := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "rl_set_latency",
			Help: "Histogram of latencies of redisSource.Set calls",
			// Exponential buckets ranging from 0.0005s to 2s
			Buckets: prometheus.ExponentialBucketsRange(0.0005, 2, 8),
		},
		[]string{"result"},
	)
	stats.MustRegister(setLatency)

	getLatency := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "rl_get_latency",
			Help: "Histogram of redisSource.Get call latencies",
			// Exponential buckets ranging from 0.0005s to 2s
			Buckets: prometheus.ExponentialBucketsRange(0.0005, 2, 8),
		},
		[]string{"result"},
	)
	stats.MustRegister(getLatency)

	deleteLatency := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "rl_delete_latency",
			Help: "Histogram of latencies of redisSource.Delete calls",
			// Exponential buckets ranging from 0.0005s to 2s
			Buckets: prometheus.ExponentialBucketsRange(0.0005, 2, 8),
		},
		[]string{"result"},
	)
	stats.MustRegister(deleteLatency)

	return &RedisSource{
		client:        client,
		timeout:       timeout,
		clk:           clk,
		setLatency:    setLatency,
		getLatency:    getLatency,
		deleteLatency: deleteLatency,
	}
}

// Set stores the TAT at the specified bucketKey ('name:id'). It returns an
// error if the operation failed and nil otherwise. If the bucketKey does not
// exist, it will be created.
func (r *RedisSource) Set(ctx context.Context, bucketKey string, tat time.Time) error {
	start := r.clk.Now()
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	err := r.client.Set(ctx, bucketKey, tat.UnixNano(), 0).Err()
	if err != nil {
		state := "failed"
		if errors.Is(err, context.DeadlineExceeded) {
			state = "deadlineExceeded"
		} else if errors.Is(err, context.Canceled) {
			state = "canceled"
		}
		r.setLatency.With(prometheus.Labels{"result": state}).Observe(time.Since(start).Seconds())
		return err
	}

	r.setLatency.With(prometheus.Labels{"result": "success"}).Observe(time.Since(start).Seconds())
	return nil
}

// Get retrieves the TAT at the specified bucketKey ('name:id'). It returns the
// TAT and nil if the operation succeeded, or an error if the operation failed.
// If the bucketKey does not exist, it returns ErrBucketNotFound.
func (r *RedisSource) Get(ctx context.Context, bucketKey string) (time.Time, error) {
	start := r.clk.Now()
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	tatNano, err := r.client.Get(ctx, bucketKey).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// Bucket key does not exist.
			r.getLatency.With(prometheus.Labels{"result": "notFound"}).Observe(time.Since(start).Seconds())
			return time.Time{}, ErrBucketNotFound
		}

		state := "failed"
		if errors.Is(err, context.DeadlineExceeded) {
			state = "deadlineExceeded"
		} else if errors.Is(err, context.Canceled) {
			state = "canceled"
		}
		r.getLatency.With(prometheus.Labels{"result": state}).Observe(time.Since(start).Seconds())
		return time.Time{}, err
	}

	r.getLatency.With(prometheus.Labels{"result": "success"}).Observe(time.Since(start).Seconds())
	return time.Unix(0, tatNano).UTC(), nil
}

// Delete deletes the TAT at the specified bucketKey ('name:id'). It returns an
// error if the operation failed and nil otherwise. A nil return value does not
// indicate that the bucketKey existed.
func (r *RedisSource) Delete(ctx context.Context, bucketKey string) error {
	start := r.clk.Now()
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	err := r.client.Del(ctx, bucketKey).Err()
	if err != nil {
		r.deleteLatency.With(prometheus.Labels{"result": "failed"}).Observe(time.Since(start).Seconds())
		return err
	}

	r.deleteLatency.With(prometheus.Labels{"result": "success"}).Observe(time.Since(start).Seconds())
	return nil
}

// Ping checks that each shard of the *redis.Ring is reachable using the PING
// command. It returns an error if any shard is unreachable and nil otherwise.
func (r *RedisSource) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	err := r.client.ForEachShard(ctx, func(ctx context.Context, shard *redis.Client) error {
		return shard.Ping(ctx).Err()
	})
	if err != nil {
		return err
	}
	return nil
}
