package rocsp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/core"
	"golang.org/x/crypto/ocsp"
)

type Metadata struct {
	shortIssuerID byte
	updated       time.Time
}

func (m Metadata) String() string {
	return fmt.Sprintf("shortIssuerID: 0x%x, updated at: %s", m.shortIssuerID, m.updated)
}

func (m Metadata) Marshal() []byte {
	var output [9]byte
	output[0] = m.shortIssuerID
	var epochSeconds uint64 = uint64(m.updated.Unix())
	binary.LittleEndian.PutUint64(output[1:], epochSeconds)
	return output[:]
}

func UnmarshalMetadata(input []byte) (Metadata, error) {
	if len(input) != 9 {
		return Metadata{}, fmt.Errorf("invalid metadata length %d", len(input))
	}
	var output Metadata
	output.shortIssuerID = input[0]
	epochSeconds := binary.LittleEndian.Uint64(input[1:])
	output.updated = time.Unix(int64(epochSeconds), 0).UTC()
	return output, nil
}

func MakeResponseKey(serial string) string {
	return fmt.Sprintf("r{%s}", serial)
}

func MakeMetadataKey(serial string) string {
	return fmt.Sprintf("m{%s}", serial)
}

type Client struct {
	rdb *redis.ClusterClient
	timeout time.Duration
	clk clock.Clock
}

func NewClient(rdb *redis.ClusterClient, timeout time.Duration, clk clock.Clock) *Client {
	return &Client {
		rdb: rdb,
		timeout: timeout,
		clk: clk,
	}
}

type WritingClient struct {
	Client
}

func NewWritingClient(rdb *redis.ClusterClient, timeout time.Duration, clk clock.Clock) *WritingClient {
	return &WritingClient {
		Client {
			rdb: rdb,
			timeout: timeout,
			clk: clk,
		},
	}
}

func (c *WritingClient) StoreResponse(respBytes []byte, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	// TODO: load issuers and pass something appropriate here instead of nil
	resp, err := ocsp.ParseResponse(respBytes, nil)
	if err != nil {
		return fmt.Errorf("parsing %d-byte response: %w", len(respBytes), err)
	}

	serial := core.SerialToString(resp.SerialNumber)

	responseKey := MakeResponseKey(serial)
	metadataKey := MakeMetadataKey(serial)

	metadataStruct := Metadata{
		updated:       resp.ThisUpdate,
		shortIssuerID: 0x99, /// XXX
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

		log.Printf("stored %s", core.SerialToString(resp.SerialNumber))
		return nil
	}, metadataKey, responseKey)
	if err != nil {
		return fmt.Errorf("transaction failed: %w", err)
	}

	return nil
}

func (c *Client) GetResponse(serial string) (*ocsp.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	responseKey := MakeResponseKey(serial)
	metadataKey := MakeMetadataKey(serial)

	val, err := c.rdb.Get(ctx, metadataKey).Result()
	if err != nil {
		return nil, fmt.Errorf("getting metadata: %w", err)
	}
	epochSeconds, err := UnmarshalMetadata([]byte(val))
	if err != nil {
		return nil, fmt.Errorf("unmarshaling metadata: %w", err)
	}
	log.Printf("retrieved metadata: %s", epochSeconds)

	val, err = c.rdb.Get(ctx, responseKey).Result()
	if err != nil {
		return nil, fmt.Errorf("getting response: %w", err)
	}
	parsedResponse, err := ocsp.ParseResponse([]byte(val), nil)
	if err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return parsedResponse, nil
}
