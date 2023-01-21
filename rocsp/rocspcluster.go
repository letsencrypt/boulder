package rocsp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/core"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
)

// TODO(#6517) remove this file and replace the Reader and Writer interfaces
// with the structs in rocsp.go.

// Reader is an interface for read-only Redis clients. It's implemented by
// CROClient and ROClient.
type Reader interface {
	GetResponse(context.Context, string) ([]byte, error)
	Ping(context.Context) error
	ScanResponses(context.Context, string) <-chan ScanResponsesResult
}

// CROClient represents a read-only Redis client.
type CROClient struct {
	rdb        *redis.ClusterClient
	timeout    time.Duration
	clk        clock.Clock
	getLatency *prometheus.HistogramVec
}

// NewClusterReadingClient creates a read-only client for use with a Redis Cluster. The
// timeout applies to all requests, though a shorter timeout can be applied on a
// per-request basis using context.Context. rdb.Options().Addrs must have at
// least one entry.
func NewClusterReadingClient(rdb *redis.ClusterClient, timeout time.Duration, clk clock.Clock, stats prometheus.Registerer) *CROClient {
	if len(rdb.Options().Addrs) == 0 {
		return nil
	}
	labels := prometheus.Labels{
		"addresses": strings.Join(rdb.Options().Addrs, ", "),
		"user":      rdb.Options().Username,
	}
	stats.MustRegister(newMetricsCollector(rdb, labels))
	getLatency := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "rocsp_get_latency",
			Help: "Histogram of latencies of rocsp.GetResponse calls with result",
			// 8 buckets, ranging from 0.5ms to 2s
			Buckets: prometheus.ExponentialBucketsRange(0.0005, 2, 8),
		},
		[]string{"result"},
	)
	stats.MustRegister(getLatency)

	return &CROClient{
		rdb:        rdb,
		timeout:    timeout,
		clk:        clk,
		getLatency: getLatency,
	}
}

func (c *CROClient) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return c.rdb.Ping(ctx).Err()
}

// Writer is an interface for read-only Redis clients. It's implemented by
// CRWClient and RWClient.
type Writer interface {
	StoreResponse(context.Context, *ocsp.Response) error
	GetResponse(context.Context, string) ([]byte, error)
	Ping(context.Context) error
	ScanResponses(context.Context, string) <-chan ScanResponsesResult
}

// WritingClient represents a Redis client that can both read and write.
type CRWClient struct {
	*CROClient
	storeResponseLatency *prometheus.HistogramVec
}

// NewWritingClient creates a WritingClient.
func NewClusterWritingClient(rdb *redis.ClusterClient, timeout time.Duration, clk clock.Clock, stats prometheus.Registerer) *CRWClient {
	storeResponseLatency := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "rocsp_store_response_latency",
			Help: "Histogram of latencies of rocsp.StoreResponse calls with result labels",
		},
		[]string{"result"},
	)
	stats.MustRegister(storeResponseLatency)
	return &CRWClient{NewClusterReadingClient(rdb, timeout, clk, stats), storeResponseLatency}
}

// StoreResponse parses the given bytes as an OCSP response, and stores it
// into Redis. The expiration time (ttl) of the Redis key is set to OCSP
// response `NextUpdate`.
func (c *CRWClient) StoreResponse(ctx context.Context, resp *ocsp.Response) error {
	start := c.clk.Now()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	serial := core.SerialToString(resp.SerialNumber)

	// Set the ttl duration to the response `NextUpdate - now()`
	ttl := time.Until(resp.NextUpdate)

	err := c.rdb.Set(ctx, serial, resp.Raw, ttl).Err()
	if err != nil {
		state := "failed"
		if errors.Is(err, context.DeadlineExceeded) {
			state = "deadlineExceeded"
		} else if errors.Is(err, context.Canceled) {
			state = "canceled"
		}
		c.storeResponseLatency.With(prometheus.Labels{"result": state}).Observe(time.Since(start).Seconds())
		return fmt.Errorf("setting response: %w", err)
	}

	c.storeResponseLatency.With(prometheus.Labels{"result": "success"}).Observe(time.Since(start).Seconds())
	return nil
}

// GetResponse fetches a response for the given serial number.
// Returns error if the OCSP response fails to parse.
func (c *CROClient) GetResponse(ctx context.Context, serial string) ([]byte, error) {
	start := c.clk.Now()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.rdb.Get(ctx, serial).Result()
	if err != nil {
		// go-redis `Get` returns redis.Nil error when key does not exist. In
		// that case return a `ErrRedisNotFound` error.
		if errors.Is(err, redis.Nil) {
			c.getLatency.With(prometheus.Labels{"result": "notFound"}).Observe(time.Since(start).Seconds())
			return nil, ErrRedisNotFound
		}

		state := "failed"
		if errors.Is(err, context.DeadlineExceeded) {
			state = "deadlineExceeded"
		} else if errors.Is(err, context.Canceled) {
			state = "canceled"
		}
		c.getLatency.With(prometheus.Labels{"result": state}).Observe(time.Since(start).Seconds())
		return nil, fmt.Errorf("getting response: %w", err)
	}

	c.getLatency.With(prometheus.Labels{"result": "success"}).Observe(time.Since(start).Seconds())
	return []byte(resp), nil
}

// ScanResponses scans Redis for all OCSP responses where the serial number matches the provided pattern.
// It returns immediately and emits results and errors on `<-chan ScanResponsesResult`. It closes the
// channel when it is done or hits an error.
func (c *CROClient) ScanResponses(ctx context.Context, serialPattern string) <-chan ScanResponsesResult {
	pattern := fmt.Sprintf("r{%s}", serialPattern)
	results := make(chan ScanResponsesResult)
	go func() {
		defer close(results)
		err := c.rdb.ForEachMaster(ctx, func(ctx context.Context, rdb *redis.Client) error {
			iter := rdb.Scan(ctx, 0, pattern, 0).Iterator()
			for iter.Next(ctx) {
				key := iter.Val()
				val, err := c.rdb.Get(ctx, key).Result()
				if err != nil {
					results <- ScanResponsesResult{Err: fmt.Errorf("getting response: %w", err)}
					continue
				}
				results <- ScanResponsesResult{Serial: key, Body: []byte(val)}
			}
			return iter.Err()
		})
		if err != nil {
			results <- ScanResponsesResult{Err: err}
			return
		}
	}()
	return results
}
