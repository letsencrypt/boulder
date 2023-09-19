package ratelimits

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
)

// Compile-time check that RedisSource implements the source interface.
var _ source = (*RedisSource)(nil)

// RedisSource is a ratelimits source backed by sharded Redis.
type RedisSource struct {
	client        *redis.Ring
	clk           clock.Clock
	setLatency    *prometheus.HistogramVec
	getLatency    *prometheus.HistogramVec
	deleteLatency *prometheus.HistogramVec
}

// NewRedisSource returns a new Redis backed source using the provided
// *redis.Ring client.
func NewRedisSource(client *redis.Ring, clk clock.Clock, stats prometheus.Registerer) *RedisSource {
	// Exponential buckets ranging from 0.0005s to 3s.
	buckets := prometheus.ExponentialBucketsRange(0.0005, 3, 8)

	setLatency := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ratelimits_set_latency",
			Help:    "Histogram of RedisSource.Set() call latencies labeled by result",
			Buckets: buckets,
		},
		[]string{"result"},
	)
	stats.MustRegister(setLatency)

	getLatency := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ratelimits_get_latency",
			Help:    "Histogram of RedisSource.Get() call latencies labeled by result",
			Buckets: buckets,
		},
		[]string{"result"},
	)
	stats.MustRegister(getLatency)

	deleteLatency := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ratelimits_delete_latency",
			Help:    "Histogram of RedisSource.Delete() call latencies labeled by result",
			Buckets: buckets,
		},
		[]string{"result"},
	)
	stats.MustRegister(deleteLatency)

	return &RedisSource{
		client:        client,
		clk:           clk,
		setLatency:    setLatency,
		getLatency:    getLatency,
		deleteLatency: deleteLatency,
	}
}

// resultForError returns a string representing the result of the operation
// based on the provided error.
func resultForError(err error) string {
	if errors.Is(redis.Nil, err) {
		// Bucket key does not exist.
		return "notFound"
	} else if errors.Is(err, context.DeadlineExceeded) {
		// Client read or write deadline exceeded.
		return "deadlineExceeded"
	} else if errors.Is(err, context.Canceled) {
		// Caller canceled the operation.
		return "canceled"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		// Dialer timed out connecting to Redis.
		return "timeout"
	}
	var redisErr redis.Error
	if errors.Is(err, redisErr) {
		// An internal error was returned by the Redis server.
		return "redisError"
	}
	return "failed"
}

// Set stores the TAT at the specified bucketKey ('name:id'). It returns an
// error if the operation failed and nil otherwise. If the bucketKey does not
// exist, it will be created.
func (r *RedisSource) Set(ctx context.Context, bucketKey string, tat time.Time) error {
	start := r.clk.Now()

	err := r.client.Set(ctx, bucketKey, tat.UnixNano(), 0).Err()
	if err != nil {
		r.setLatency.With(prometheus.Labels{"result": resultForError(err)}).Observe(time.Since(start).Seconds())
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

	tatNano, err := r.client.Get(ctx, bucketKey).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// Bucket key does not exist.
			r.getLatency.With(prometheus.Labels{"result": "notFound"}).Observe(time.Since(start).Seconds())
			return time.Time{}, ErrBucketNotFound
		}
		r.getLatency.With(prometheus.Labels{"result": resultForError(err)}).Observe(time.Since(start).Seconds())
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

	err := r.client.Del(ctx, bucketKey).Err()
	if err != nil {
		r.deleteLatency.With(prometheus.Labels{"result": resultForError(err)}).Observe(time.Since(start).Seconds())
		return err
	}

	r.deleteLatency.With(prometheus.Labels{"result": "success"}).Observe(time.Since(start).Seconds())
	return nil
}

// Ping checks that each shard of the *redis.Ring is reachable using the PING
// command. It returns an error if any shard is unreachable and nil otherwise.
func (r *RedisSource) Ping(ctx context.Context) error {
	err := r.client.ForEachShard(ctx, func(ctx context.Context, shard *redis.Client) error {
		return shard.Ping(ctx).Err()
	})
	if err != nil {
		return err
	}
	return nil
}
