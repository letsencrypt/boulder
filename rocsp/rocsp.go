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
	var epochSeconds uint64 = uint64(m.ThisUpdate.Unix())
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

// Client represents a read-only Redis client.
type Client struct {
	rdb     *redis.ClusterClient
	timeout time.Duration
	clk     clock.Clock
	rdc     metricsCollector
}

// NewClient creates a Client. The timeout applies to all requests, though a shorter timeout can be
// applied on a per-request basis using context.Context.
func NewClient(rdb *redis.ClusterClient, timeout time.Duration, clk clock.Clock, stats prometheus.Registerer) *Client {
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

	return &Client{
		rdb:     rdb,
		timeout: timeout,
		clk:     clk,
		rdc:     dbc,
	}
}

// WritingClient represents a Redis client that can both read and write.
type WritingClient struct {
	*Client
}

// NewWritingClient creates a WritingClient.
func NewWritingClient(rdb *redis.ClusterClient, timeout time.Duration, clk clock.Clock, stats prometheus.Registerer) *WritingClient {
	return &WritingClient{NewClient(rdb, timeout, clk, stats)}
}

// StoreResponse parses the given bytes as an OCSP response, and stores it into
// Redis, updating both the metadata and response keys. ShortIssuerID is an
// arbitrarily assigned byte that unique identifies each issuer. Must be the
// same across OCSP components. Returns error if the OCSP response fails to
// parse.
func (c *WritingClient) StoreResponse(ctx context.Context, respBytes []byte, shortIssuerID byte, ttl time.Duration) error {
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
		return fmt.Errorf("transaction failed: %w", err)
	}

	return nil
}

// GetResponse fetches a response for the given serial number.
// Returns error if the OCSP response fails to parse.
// Does not check the metadata field.
func (c *Client) GetResponse(ctx context.Context, serial string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	responseKey := MakeResponseKey(serial)

	resp, err := c.rdb.Get(ctx, responseKey).Result()
	if err != nil {
		// go-redis `Get` returns redis.Nil error when key does not exist. In
		// that case return a `ErrRedisNotFound` error.
		if errors.Is(err, redis.Nil) {
			return nil, ErrRedisNotFound
		}
		return nil, fmt.Errorf("getting response: %w", err)
	}

	return []byte(resp), nil
}

// GetMetadata fetches the metadata for the given serial number.
func (c *Client) GetMetadata(ctx context.Context, serial string) (*Metadata, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	metadataKey := MakeMetadataKey(serial)

	resp, err := c.rdb.Get(ctx, metadataKey).Result()
	if err != nil {
		// go-redis `Get` returns redis.Nil error when key does not exist. In
		// that case return a `ErrRedisNotFound` error.
		if errors.Is(err, redis.Nil) {
			return nil, ErrRedisNotFound
		}
		return nil, fmt.Errorf("getting metadata: %w", err)
	}
	metadata, err := UnmarshalMetadata([]byte(resp))
	if err != nil {
		return nil, fmt.Errorf("unmarshaling metadata: %w", err)
	}
	return &metadata, nil
}
