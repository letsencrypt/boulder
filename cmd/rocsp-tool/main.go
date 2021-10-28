package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/test/ocsp/helper"
	"golang.org/x/crypto/ocsp"
)

type config struct {
	ROCSPTool struct {
		Redis struct {
			cmd.PasswordConfig
			TLS      cmd.TLSConfig
			Username string
			Addrs    []string
			Timeout  cmd.ConfigDuration
		}
		Issuers []string
	}
}

func main() {
	if err := main2(); err != nil {
		log.Fatal(err)
	}
}

func main2() error {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	conf := c.ROCSPTool

	password, err := conf.Redis.PasswordConfig.Pass()
	if err != nil {
		return fmt.Errorf("loading password: %w", err)
	}

	tlsConfig, err := conf.Redis.TLS.Load()
	if err != nil {
		return err
	}

	timeout := conf.Redis.Timeout.Duration

	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.MaxVersion = tls.VersionTLS13
	rdb := redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:     conf.Redis.Addrs,
		Username:  conf.Redis.Username,
		Password:  password,
		TLSConfig: tlsConfig,
	})

	val, err := rdb.Ping(context.TODO()).Result()
	if err != nil {
		return err
	}

	log.Printf("ping: %s\n", val)
	for _, respFile := range flag.Args() {
		respBytes, err := ioutil.ReadFile(respFile)
		if err != nil {
			return fmt.Errorf("reading response file %q: %w", respFile, err)
		}
		err = storeResponse(rdb, respBytes, timeout)
		if err != nil {
			return fmt.Errorf("storing response: %w", err)
		}

		resp, err := ocsp.ParseResponse(respBytes, nil)
		if err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}
		retrievedResponse, err := getResponse(rdb, core.SerialToString(resp.SerialNumber), timeout)
		if err != nil {
			return fmt.Errorf("getting response: %w", err)
		}
		log.Printf("retrieved %s", helper.PrettyResponse(retrievedResponse))
	}
	return nil
}

type metadata struct {
	shortIssuerID byte
	updated       time.Time
}

func (m metadata) String() string {
	return fmt.Sprintf("shortIssuerID: 0x%x, updated at: %s", m.shortIssuerID, m.updated)
}

func (m metadata) marshal() []byte {
	var output [9]byte
	output[0] = m.shortIssuerID
	var epochSeconds uint64 = uint64(m.updated.Unix())
	binary.LittleEndian.PutUint64(output[1:], epochSeconds)
	return output[:]
}

func unmarshalMetadata(input []byte) (metadata, error) {
	if len(input) != 9 {
		return metadata{}, fmt.Errorf("invalid metadata length %d", len(input))
	}
	var output metadata
	output.shortIssuerID = input[0]
	epochSeconds := binary.LittleEndian.Uint64(input[1:])
	output.updated = time.Unix(int64(epochSeconds), 0).UTC()
	return output, nil
}

func makeResponseKey(serial string) string {
	return fmt.Sprintf("r{%s}", serial)
}

func makeMetadataKey(serial string) string {
	return fmt.Sprintf("m{%s}", serial)
}

func storeResponse(rdb *redis.ClusterClient, respBytes []byte, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// TODO: load issuers and pass something appropriate here instead of nil
	resp, err := ocsp.ParseResponse(respBytes, nil)
	if err != nil {
		return fmt.Errorf("parsing %d-byte response: %w", len(respBytes), err)
	}

	serial := core.SerialToString(resp.SerialNumber)

	responseKey := makeResponseKey(serial)
	metadataKey := makeMetadataKey(serial)

	metadataStruct := metadata{
		updated:       resp.ThisUpdate,
		shortIssuerID: 0x99, /// XXX
	}
	metadataValue := metadataStruct.marshal()

	// Note: Here we set the TTL to slightly more than the lifetime of the
	// OCSP response. In ocsp-updater we'll want to set it to the lifetime
	// of the certificate, so that the metadata field doesn't fall out of
	// storage even if we are down for days. However, in this tool we don't
	// have the full certificate, so this will do.
	ttl := resp.NextUpdate.Sub(time.Now()) + time.Hour

	err = rdb.Watch(ctx, func(tx *redis.Tx) error {
		log.Printf("storing response for %s, generated %s, ttl %g hours",
			core.SerialToString(resp.SerialNumber),
			resp.ThisUpdate,
			ttl.Hours())

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

func getResponse(rdb *redis.ClusterClient, serial string, timeout time.Duration) (*ocsp.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	responseKey := makeResponseKey(serial)
	metadataKey := makeMetadataKey(serial)

	val, err := rdb.Get(ctx, metadataKey).Result()
	if err != nil {
		return nil, fmt.Errorf("getting metadata: %w", err)
	}
	epochSeconds, err := unmarshalMetadata([]byte(val))
	if err != nil {
		return nil, fmt.Errorf("unmarshaling metadata: %w", err)
	}
	log.Printf("retrieved metadata: %s", epochSeconds)

	val, err = rdb.Get(ctx, responseKey).Result()
	if err != nil {
		return nil, fmt.Errorf("getting response: %w", err)
	}
	parsedResponse, err := ocsp.ParseResponse([]byte(val), nil)
	if err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return parsedResponse, nil
}
