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
	"golang.org/x/crypto/ocsp"
)

type config struct {
	OCSPTool struct {
		TLS   TLSConfig
		Redis struct {
			Username string
			Password string
			Addr     string
		}
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

	tlsConfig, err := c.Load()
	if err != nil {
		return err
	}

	tlsConfig.MinVersion = tls.VersionTLS13
	rdb := redis.NewClient(&redis.Options{
		Addr:      c.Addr,
		Username:  c.Username,
		Password:  c.Password,
		DB:        0, // use default DB
		TLSConfig: tlsConfig,
	})

	for _, respFile := range os.Args[1:] {
		respBytes, err := ioutil.ReadFile(respFile)
		if err != nil {
			return fmt.Errorf("reading response file %q: %w", respFile, err)
		}
		storeResponse(rdb, respBytes)
	}
	return nil
}

func storeResponse(rdb *redis.Client, respBytes []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := ocsp.ParseResponse(respBytes, nil)
	if err != nil {
		return fmt.Errorf("parsing %d-byte response: %w", len(respBytes), err)
	}

	issuerID := "TODO"
	responseKey := "r{" + issuerID + string(resp.SerialNumber.Bytes()) + "}"
	metadataKey := "m{" + issuerID + string(resp.SerialNumber.Bytes()) + "}"

	var epochSeconds uint64 = uint64(resp.ThisUpdate.Unix())
	var metadataValue [8]byte
	binary.LittleEndian.PutUint64(metadataValue[:], epochSeconds)

	ttl := time.Now().Sub(resp.ThisUpdate)

	err = rdb.Watch(ctx, func(tx *redis.Tx) error {
		log.Printf("storing response for %s, generated %s (epoch-seconds %d), ttl %g hours",
			core.SerialToString(resp.SerialNumber),
			resp.ThisUpdate,
			epochSeconds,
			ttl.Hours())

		err = tx.Set(ctx, responseKey, respBytes, ttl).Err()
		if err != nil {
			return fmt.Errorf("setting response: %w", err)
		}

		err = tx.Set(ctx, metadataKey, respBytes, ttl).Err()
		if err != nil {
			return fmt.Errorf("setting metadata: %w", err)
		}

		log.Printf("stored %s", core.SerialToString(resp.SerialNumber))
		return nil
	}, "...")

	if err != nil {
		return fmt.Errorf("transaction failed: %w", err)
	}
	return nil
}
