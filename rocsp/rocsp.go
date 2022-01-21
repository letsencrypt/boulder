package rocsp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/core"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
)

var ErrRedisNotFound = errors.New("redis key not found")

// Metadata represents information stored with the 'm' prefix in the Redis DB:
// information required to maintain or serve the response, but not the response
// itself.
type Metadata struct {
	ShortIssuerID byte
	// ThisUpdate contains the ThisUpdate time of the stored OCSP response.
	ThisUpdate time.Time
}

// String implements pretty-printing of Metadata
func (m Metadata) String() string {
	return fmt.Sprintf("shortIssuerID: 0x%x, updated at: %s", m.ShortIssuerID, m.ThisUpdate)
}

// Marshal turns a metadata into a slice of 9 bytes for writing into Redis.
// Storing these always as 9 bytes gives us some potential to change the
// storage format non-disruptively in the future, so long as we can distinguish
// on the length of the stored value.
func (m Metadata) Marshal() []byte {
	var output [9]byte
	output[0] = m.ShortIssuerID
	epochSeconds := uint64(m.ThisUpdate.Unix())
	binary.LittleEndian.PutUint64(output[1:], epochSeconds)
	return output[:]
}

// UnmarshalMetadata takes data from Redis and turns it into a Metadata object.
func UnmarshalMetadata(input []byte) (Metadata, error) {
	if len(input) != 9 {
		return Metadata{}, fmt.Errorf("invalid metadata length %d", len(input))
	}
	var output Metadata
	output.ShortIssuerID = input[0]
	epochSeconds := binary.LittleEndian.Uint64(input[1:])
	output.ThisUpdate = time.Unix(int64(epochSeconds), 0).UTC()
	return output, nil
}

// MakeResponseKey generates a Redis key string under which a response with the
// given serial should be stored.
func MakeResponseKey(serial string) string {
	return fmt.Sprintf("r{%s}", serial)
}

// MakeMetadataKey generates a Redis key string under which metadata for the
// response with the given serial should be stored.
func MakeMetadataKey(serial string) string {
	return fmt.Sprintf("m{%s}", serial)
}

func SerialFromResponseKey(key string) (string, error) {
	if len(key) != 39 || key[0:2] != "r{" || key[38:39] != "}" {
		return "", fmt.Errorf("malformed Redis OCSP response key %q", key)
	}
	return key[2:38], nil
}

func SerialFromMetadataKey(key string) (string, error) {
	if len(key) != 39 || key[0:2] != "m{" || key[38:39] != "}" {
		return "", fmt.Errorf("malformed Redis OCSP metadata key %q", key)
	}
	return key[2:38], nil
}

// Client represents a read-only Redis client.
type Client struct {
	rdb        *redis.ClusterClient
	timeout    time.Duration
	clk        clock.Clock
	rdc        metricsCollector
	getLatency *prometheus.HistogramVec
}

// NewClient creates a Client. The timeout applies to all requests, though a shorter timeout can be
// applied on a per-request basis using context.Context.
func NewClient(
	rdb *redis.ClusterClient,
	timeout time.Duration,
	clk clock.Clock,
	stats prometheus.Registerer,
) *Client {
	dbc := metricsCollector{rdb: rdb}

	labels := prometheus.Labels{"address": rdb.Options().Addrs[0], "user": rdb.Options().Username}
	dbc.hits = prometheus.NewDesc(
		"redis_hits",
		"Number of times free connection was found in the pool.",
		nil, labels)
	dbc.misses = prometheus.NewDesc(
		"redis_misses",
		"Number of times free connection was NOT found in the pool.",
		nil, labels)
	dbc.timeouts = prometheus.NewDesc(
		"redis_timeouts",
		"Number of times a wait timeout occurred.",
		nil, labels)
	dbc.totalConns = prometheus.NewDesc(
		"redis_total_conns",
		"Number of total connections in the pool.",
		nil, labels)
	dbc.idleConns = prometheus.NewDesc(
		"redis_idle_conns",
		"Number of idle connections in the pool.",
		nil, labels)
	dbc.staleConns = prometheus.NewDesc(
		"redis_stale_conns",
		"Number of stale connections removed from the pool.",
		nil, labels)
	stats.MustRegister(dbc)
	getLatency := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "rocsp_get_latency",
			Help: "Histogram of latencies of rocsp.GetResponse and rocsp.GetMetadata calls with result and method labels",
		},
		[]string{"result", "method"},
	)
	stats.MustRegister(getLatency)

	return &Client{
		rdb:        rdb,
		timeout:    timeout,
		clk:        clk,
		rdc:        dbc,
		getLatency: getLatency,
	}
}

// WritingClient represents a Redis client that can both read and write.
type WritingClient struct {
	*Client
	storeResponseLatency *prometheus.HistogramVec
}

// NewWritingClient creates a WritingClient.
func NewWritingClient(rdb *redis.ClusterClient, timeout time.Duration, clk clock.Clock, stats prometheus.Registerer) *WritingClient {
	storeResponseLatency := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "rocsp_store_response_latency",
			Help: "Histogram of latencies of rocsp.StoreResponse calls with result labels",
		},
		[]string{"result"},
	)
	stats.MustRegister(storeResponseLatency)
	return &WritingClient{NewClient(rdb, timeout, clk, stats), storeResponseLatency}
}

// StoreResponse parses the given bytes as an OCSP response, and stores it into
// Redis, updating both the metadata and response keys. ShortIssuerID is an
// arbitrarily assigned byte that unique identifies each issuer. Must be the
// same across OCSP components. Returns error if the OCSP response fails to
// parse.
func (c *WritingClient) StoreResponse(ctx context.Context, respBytes []byte, shortIssuerID byte, ttl time.Duration) error {
	start := c.clk.Now()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := ocsp.ParseResponse(respBytes, nil)
	if err != nil {
		return fmt.Errorf("parsing %d-byte response: %w", len(respBytes), err)
	}

	serial := core.SerialToString(resp.SerialNumber)

	responseKey := MakeResponseKey(serial)
	metadataKey := MakeMetadataKey(serial)

	metadataStruct := Metadata{
		ThisUpdate:    resp.ThisUpdate,
		ShortIssuerID: shortIssuerID,
	}
	metadataValue := metadataStruct.Marshal()

	err = c.rdb.Watch(ctx, func(tx *redis.Tx) error {
		err = tx.Set(ctx, responseKey, respBytes, ttl).Err()
		if err != nil {
			return fmt.Errorf("setting response: %w", err)
		}

		err = tx.Set(ctx, metadataKey, metadataValue, ttl).Err()
		if err != nil {
			return fmt.Errorf("setting metadata: %w", err)
		}

		return nil
	}, metadataKey, responseKey)
	if err != nil {
		state := "failed"
		if errors.Is(err, context.DeadlineExceeded) {
			state = "deadlineExceeded"
		} else if errors.Is(err, context.Canceled) {
			state = "canceled"
		}
		c.storeResponseLatency.With(prometheus.Labels{"result": state}).Observe(time.Since(start).Seconds())
		return fmt.Errorf("transaction failed: %w", err)
	}

	c.storeResponseLatency.With(prometheus.Labels{"result": "success"}).Observe(time.Since(start).Seconds())
	return nil
}

// GetResponse fetches a response for the given serial number.
// Returns error if the OCSP response fails to parse.
// Does not check the metadata field.
func (c *Client) GetResponse(ctx context.Context, serial string) ([]byte, error) {
	start := c.clk.Now()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	responseKey := MakeResponseKey(serial)

	resp, err := c.rdb.Get(ctx, responseKey).Result()
	if err != nil {
		// go-redis `Get` returns redis.Nil error when key does not exist. In
		// that case return a `ErrRedisNotFound` error.
		if errors.Is(err, redis.Nil) {
			c.getLatency.With(prometheus.Labels{"result": "notFound", "method": "GetResponse"}).Observe(time.Since(start).Seconds())
			return nil, ErrRedisNotFound
		}

		state := "failed"
		if errors.Is(err, context.DeadlineExceeded) {
			state = "deadlineExceeded"
		} else if errors.Is(err, context.Canceled) {
			state = "canceled"
		}
		c.getLatency.With(prometheus.Labels{"result": state, "method": "GetResponse"}).Observe(time.Since(start).Seconds())
		return nil, fmt.Errorf("getting response: %w", err)
	}

	c.getLatency.With(prometheus.Labels{"result": "success", "method": "GetResponse"}).Observe(time.Since(start).Seconds())
	return []byte(resp), nil
}

// GetMetadata fetches the metadata for the given serial number.
func (c *Client) GetMetadata(ctx context.Context, serial string) (*Metadata, error) {
	start := c.clk.Now()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	metadataKey := MakeMetadataKey(serial)

	resp, err := c.rdb.Get(ctx, metadataKey).Result()
	if err != nil {
		// go-redis `Get` returns redis.Nil error when key does not exist. In
		// that case return a `ErrRedisNotFound` error.
		if errors.Is(err, redis.Nil) {
			c.getLatency.With(prometheus.Labels{"result": "notFound", "method": "GetMetadata"}).Observe(time.Since(start).Seconds())
			return nil, ErrRedisNotFound
		}

		state := "failed"
		if errors.Is(err, context.DeadlineExceeded) {
			state = "deadlineExceeded"
		} else if errors.Is(err, context.Canceled) {
			state = "canceled"
		}
		c.getLatency.With(prometheus.Labels{"result": state, "method": "GetMetadata"}).Observe(time.Since(start).Seconds())
		return nil, fmt.Errorf("getting metadata: %w", err)
	}
	metadata, err := UnmarshalMetadata([]byte(resp))
	if err != nil {
		c.getLatency.With(prometheus.Labels{"result": "failed", "method": "GetMetadata"}).Observe(time.Since(start).Seconds())
		return nil, fmt.Errorf("unmarshaling metadata: %w", err)
	}

	c.getLatency.With(prometheus.Labels{"result": "success", "method": "GetMetadata"}).Observe(time.Since(start).Seconds())
	return &metadata, nil
}

// ScanResponsesResult represents a single OCSP response entry in redis.
// `Serial` is the stringified serial number of the response. `Body` is the
// DER bytes of the response. If this object represents an error, `Err` will
// be non-nil and the other entries will have their zero values.
type ScanResponsesResult struct {
	Serial string
	Body   []byte
	Err    error
}

// ScanResponses scans Redis for all OCSP responses where the serial number matches the provided pattern.
// It returns immediately and emits results and errors on `<-chan ScanResponsesResult`. It closes the
// channel when it is done or hits an error.
func (c *Client) ScanResponses(ctx context.Context, serialPattern string) <-chan ScanResponsesResult {
	pattern := fmt.Sprintf("r{%s}", serialPattern)
	results := make(chan ScanResponsesResult)
	go func() {
		defer close(results)
		err := c.rdb.ForEachMaster(ctx, func(ctx context.Context, rdb *redis.Client) error {
			iter := rdb.Scan(ctx, 0, pattern, 0).Iterator()
			for iter.Next(ctx) {
				key := iter.Val()
				serial, err := SerialFromResponseKey(key)
				if err != nil {
					results <- ScanResponsesResult{Err: err}
					continue
				}
				val, err := c.rdb.Get(ctx, key).Result()
				if err != nil {
					results <- ScanResponsesResult{Err: fmt.Errorf("getting metadata: %w", err)}
					continue
				}
				results <- ScanResponsesResult{Serial: serial, Body: []byte(val)}
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

// ScanMetadataResult represents a single OCSP response entry in redis.
// `Serial` is the stringified serial number of the response. `Metadata` is the
// parsed metadata. If this object represents an error, `Err` will
// be non-nil and the other entries will have their zero values.
type ScanMetadataResult struct {
	Serial   string
	Metadata *Metadata
	Err      error
}

// ScanMetadata scans Redis for the metadata of all OCSP responses where the serial number matches
// the provided pattern. It returns immediately and emits results and errors on
// `<-chan ScanResponsesResult`. It closes the channel when it is done or hits an error.
func (c *Client) ScanMetadata(ctx context.Context, serialPattern string) <-chan ScanMetadataResult {
	pattern := fmt.Sprintf("m{%s}", serialPattern)
	results := make(chan ScanMetadataResult)
	go func() {
		defer close(results)
		var cursor uint64
		for {
			var keys []string
			var err error
			keys, cursor, err = c.rdb.Scan(ctx, cursor, pattern, 10).Result()
			if err != nil {
				results <- ScanMetadataResult{Err: err}
				return
			}
			if cursor == 0 {
				return
			}
			for _, key := range keys {
				serial, err := SerialFromMetadataKey(key)
				if err != nil {
					results <- ScanMetadataResult{Err: err}
					return
				}
				m, err := c.GetMetadata(ctx, serial)
				if err != nil {
					results <- ScanMetadataResult{Err: err}
					return
				}
				results <- ScanMetadataResult{Serial: serial, Metadata: m}
			}
		}
	}()
	return results
}
