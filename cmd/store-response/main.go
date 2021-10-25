package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/letsencrypt/boulder/core"
	"golang.org/x/crypto/ocsp"
)

func main() {
	if err := main2(); err != nil {
		log.Fatal(err)
	}
}

func main2() error {
	cert, err := tls.LoadX509KeyPair("test/redis-tls/boulder/cert.pem", "test/redis-tls/boulder/key.pem")
	if err != nil {
		return fmt.Errorf("loading cert and key: %w", err)
	}

	rootBytes, err := ioutil.ReadFile("test/redis-tls/minica.pem")
	if err != nil {
		return fmt.Errorf("loading root: %w", err)
	}
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(rootBytes); !ok {
		return fmt.Errorf("failed to load roots")
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     "boulder-redis:4218",
		Username: "ocsp-updater",
		Password: "e4e9ce7845cb6adbbc44fb1d9deb05e6b4dc1386",
		DB:       0, // use default DB
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
			RootCAs:      roots,
		},
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

	log.Printf("storing response for %s, generated %s, epoch-seconds %d",
		core.SerialToString(resp.SerialNumber),
		resp.ThisUpdate,
		epochSeconds)

	err = rdb.Set(ctx, responseKey, respBytes, 0).Err()
	if err != nil {
		return fmt.Errorf("setting response: %w", err)
	}

	err = rdb.Set(ctx, metadataKey, respBytes, 0).Err()
	if err != nil {
		return fmt.Errorf("setting metadata: %w", err)
	}

	log.Printf("stored %s", core.SerialToString(resp.SerialNumber))
	return nil
}
