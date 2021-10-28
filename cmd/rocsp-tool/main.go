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
	ROCSPTool struct {
		Redis struct {
			cmd.PasswordConfig
			TLS   cmd.TLSConfig
			Username string
			Addr     string
			Timeout cmd.ConfigDuration
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

	   timeout  := conf.Redis.Timeout.Duration

	   log.Print("username", conf.Redis.Username, "pass", password)
       tlsConfig.MinVersion = tls.VersionTLS13
       tlsConfig.MaxVersion = tls.VersionTLS13
       rdb := redis.NewClient(&redis.Options{
               Addr:      conf.Redis.Addr,
               Username:  conf.Redis.Username,
               Password:  password,
               DB:        0, // use default DB
               TLSConfig: tlsConfig,
       })

       for _, respFile := range flag.Args() {
               respBytes, err := ioutil.ReadFile(respFile)
               if err != nil {
                       return fmt.Errorf("reading response file %q: %w", respFile, err)
               }
               err = storeResponse(rdb, respBytes, timeout)
               if err != nil {
                       return fmt.Errorf("storing response: %w", err)
               }
       }
       return nil
}

func storeResponse(rdb *redis.Client, respBytes []byte, timeout time.Duration) error {
       ctx, cancel := context.WithTimeout(context.Background(), timeout)
       defer cancel()

       // TODO: load issuers and pass something appropriate here instead of nil
       resp, err := ocsp.ParseResponse(respBytes, nil)
       if err != nil {
               return fmt.Errorf("parsing %d-byte response: %w", len(respBytes), err)
       }

       issuerID := "TODO"
       // TODO: replace any `{` in SerialNumber
       // TODO: add assertion about length of SerialNumber.Bytes()
       responseKey := "r{" + issuerID + string(resp.SerialNumber.Bytes()) + "}"
       metadataKey := "m{" + issuerID + string(resp.SerialNumber.Bytes()) + "}"

       var epochSeconds uint64 = uint64(resp.ThisUpdate.Unix())
       var metadataValue []byte = make([]byte, 8, 8)
       binary.LittleEndian.PutUint64(metadataValue, epochSeconds)

       // TODO: maybe the length of the certificate?
       ttl := resp.NextUpdate.Sub(time.Now()) + time.Hour

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

               err = tx.Set(ctx, metadataKey, metadataValue, ttl).Err()
               if err != nil {
                       return fmt.Errorf("setting metadata: %w", err)
               }

               log.Printf("stored %s", core.SerialToString(resp.SerialNumber))
               return nil
       }, "TODO")
       if err != nil {
               return fmt.Errorf("transaction failed: %w", err)
       }
       return nil
}
