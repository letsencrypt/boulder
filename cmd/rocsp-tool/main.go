package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/rocsp"
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

	clk := cmd.Clock()
	timeout := conf.Redis.Timeout.Duration

	rdb := redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:     conf.Redis.Addrs,
		Username:  conf.Redis.Username,
		Password:  password,
		TLSConfig: tlsConfig,
	})
	client := rocsp.NewWritingClient(rdb, timeout, clk)

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
		resp, err := ocsp.ParseResponse(respBytes, nil)
		if err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}
		// Note: Here we set the TTL to slightly more than the lifetime of the
		// OCSP response. In ocsp-updater we'll want to set it to the lifetime
		// of the certificate, so that the metadata field doesn't fall out of
		// storage even if we are down for days. However, in this tool we don't
		// have the full certificate, so this will do.
		ttl := resp.NextUpdate.Sub(clk.Now()) + time.Hour

		log.Printf("storing response for %s, generated %s, ttl %g hours",
			core.SerialToString(resp.SerialNumber),
			resp.ThisUpdate,
			ttl.Hours())

		err = client.StoreResponse(respBytes, ttl)
		if err != nil {
			return fmt.Errorf("storing response: %w", err)
		}

		retrievedResponse, err := client.GetResponse(core.SerialToString(resp.SerialNumber))
		if err != nil {
			return fmt.Errorf("getting response: %w", err)
		}
		log.Printf("retrieved %s", helper.PrettyResponse(retrievedResponse))
	}
	return nil
}
