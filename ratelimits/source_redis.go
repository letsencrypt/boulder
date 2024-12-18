package ratelimits

import (
	"context"
	"errors"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
)

// Compile-time check that RedisSource implements the source interface.
var _ Source = (*RedisSource)(nil)

// RedisSource is a ratelimits source backed by sharded Redis.
type RedisSource struct {
	client *redis.Ring
	clk    clock.Clock
}

// NewRedisSource returns a new Redis backed source using the provided
// *redis.Ring client.
func NewRedisSource(client *redis.Ring, clk clock.Clock, stats prometheus.Registerer) *RedisSource {
	return &RedisSource{
		client: client,
		clk:    clk,
	}
}

// BatchSet stores TATs at the specified bucketKeys using a pipelined Redis
// Transaction in order to reduce the number of round-trips to each Redis shard.
func (r *RedisSource) BatchSet(ctx context.Context, buckets map[string]time.Time) error {
	pipeline := r.client.Pipeline()
	for bucketKey, tat := range buckets {
		// Set a TTL of TAT + 10 minutes to account for clock skew.
		ttl := tat.UTC().Sub(r.clk.Now()) + 10*time.Minute
		pipeline.Set(ctx, bucketKey, tat.UTC().UnixNano(), ttl)
	}
	_, err := pipeline.Exec(ctx)
	if err != nil {
		return err
	}
	return nil
}

// BatchSetNotExisting attempts to set TATs for the specified bucketKeys if they
// do not already exist. Returns a map indicating which keys already existed.
func (r *RedisSource) BatchSetNotExisting(ctx context.Context, buckets map[string]time.Time) (map[string]bool, error) {
	pipeline := r.client.Pipeline()
	cmds := make(map[string]*redis.BoolCmd, len(buckets))
	for bucketKey, tat := range buckets {
		// Set a TTL of TAT + 10 minutes to account for clock skew.
		ttl := tat.UTC().Sub(r.clk.Now()) + 10*time.Minute
		cmds[bucketKey] = pipeline.SetNX(ctx, bucketKey, tat.UTC().UnixNano(), ttl)
	}
	_, err := pipeline.Exec(ctx)
	if err != nil {
		return nil, err
	}

	alreadyExists := make(map[string]bool, len(buckets))
	for bucketKey, cmd := range cmds {
		success, err := cmd.Result()
		if err != nil {
			return nil, err
		}
		if !success {
			alreadyExists[bucketKey] = true
		}
	}
	return alreadyExists, nil
}

// BatchIncrement updates TATs for the specified bucketKeys using a pipelined
// Redis Transaction in order to reduce the number of round-trips to each Redis
// shard.
func (r *RedisSource) BatchIncrement(ctx context.Context, buckets map[string]increment) error {
	pipeline := r.client.Pipeline()
	for bucketKey, incr := range buckets {
		pipeline.IncrBy(ctx, bucketKey, incr.cost.Nanoseconds())
		pipeline.Expire(ctx, bucketKey, incr.ttl)
	}
	_, err := pipeline.Exec(ctx)
	if err != nil {
		return err
	}
	return nil
}

// Get retrieves the TAT at the specified bucketKey. If the bucketKey does not
// exist, ErrBucketNotFound is returned.
func (r *RedisSource) Get(ctx context.Context, bucketKey string) (time.Time, error) {
	tatNano, err := r.client.Get(ctx, bucketKey).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// Bucket key does not exist.
			return time.Time{}, ErrBucketNotFound
		}
		return time.Time{}, err
	}
	return time.Unix(0, tatNano).UTC(), nil
}

// BatchGet retrieves the TATs at the specified bucketKeys using a pipelined
// Redis Transaction in order to reduce the number of round-trips to each Redis
// shard. If a bucketKey does not exist, it WILL NOT be included in the returned
// map.
func (r *RedisSource) BatchGet(ctx context.Context, bucketKeys []string) (map[string]time.Time, error) {
	pipeline := r.client.Pipeline()
	for _, bucketKey := range bucketKeys {
		pipeline.Get(ctx, bucketKey)
	}
	results, err := pipeline.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, err
	}

	tats := make(map[string]time.Time, len(bucketKeys))
	for i, result := range results {
		tatNano, err := result.(*redis.StringCmd).Int64()
		if err != nil {
			if !errors.Is(err, redis.Nil) {
				// This should never happen as any errors should have been
				// caught after the pipeline.Exec() call.
				return nil, err
			}
			// Bucket key does not exist.
			continue
		}
		tats[bucketKeys[i]] = time.Unix(0, tatNano).UTC()
	}
	return tats, nil
}

// Delete deletes the TAT at the specified bucketKey ('name:id'). A nil return
// value does not indicate that the bucketKey existed.
func (r *RedisSource) Delete(ctx context.Context, bucketKey string) error {
	err := r.client.Del(ctx, bucketKey).Err()
	if err != nil {
		return err
	}
	return nil
}

// Ping checks that each shard of the *redis.Ring is reachable using the PING
// command.
func (r *RedisSource) Ping(ctx context.Context) error {
	err := r.client.ForEachShard(ctx, func(ctx context.Context, shard *redis.Client) error {
		return shard.Ping(ctx).Err()
	})
	if err != nil {
		return err
	}
	return nil
}
