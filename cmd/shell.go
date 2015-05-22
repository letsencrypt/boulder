// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// This package provides utilities that underlie the specific commands.
// The idea is to make the specific command files very small, e.g.:
//
//    func main() {
//      app := cmd.NewAppShell("command-name")
//      app.Action = func(c cmd.Config) {
//        // command logic
//      }
//      app.Run()
//    }
//
// All commands share the same invocation pattern.  They take a single
// parameter "-config", which is the name of a JSON file containing
// the configuration for the app.  This JSON file is unmarshalled into
// a Config object, which is provided to the app.

package cmd

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	// A dummy reference to the cfssl command line so it gets picked up by
	// `godep save -r ./...`
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/cmd/cfssl"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"
	"github.com/letsencrypt/boulder/ca"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
)

// Config stores configuration parameters that applications
// will need.  For simplicity, we just lump them all into
// one struct, and use encoding/json to read it from a file.
//
// Note: NO DEFAULTS are provided.
type Config struct {
	// General
	AMQP struct {
		Server string
		RA     QueuePair
		VA     QueuePair
		SA     QueuePair
		CA     QueuePair
	}

	WFE struct {
		BaseURL       string
		ListenAddress string
	}

	CA ca.Config

	SA struct {
		DBDriver string
		DBName   string
	}

	Statsd struct {
		Server string
		Prefix string
	}

	Syslog struct {
		Network string
		Server  string
		Tag     string
	}

	Mail struct {
		Server   string
		Port     string
		Username string
		Password string
	}

	OCSP struct {
		DBDriver string
		DBName   string
		Path     string
	}

	SubscriberAgreementURL string
}

// QueuePair describes a client-server pair of queue names
type QueuePair struct {
	Client string
	Server string
}

// AppShell contains CLI Metadata
type AppShell struct {
	Action func(Config)
	app    *cli.App
}

// NewAppShell creates a basic AppShell object containing CLI metadata
func NewAppShell(name string) (shell *AppShell) {
	app := cli.NewApp()

	app.Name = name
	app.Version = "0.0.0"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "config",
			Value:  "config.json",
			EnvVar: "BOULDER_CONFIG",
		},
	}

	return &AppShell{app: app}
}

// Run begins the application context, reading config and passing
// control to the default commandline action.
func (as *AppShell) Run() {
	as.app.Action = func(c *cli.Context) {
		configFileName := c.GlobalString("config")
		configJSON, err := ioutil.ReadFile(configFileName)
		FailOnError(err, "Unable to read config file")

		var config Config
		err = json.Unmarshal(configJSON, &config)
		FailOnError(err, "Failed to read configuration")

		as.Action(config)
	}

	err := as.app.Run(os.Args)
	FailOnError(err, "Failed to run application")
}

// FailOnError exits and prints an error message if we encountered a problem
func FailOnError(err error, msg string) {
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		panic(fmt.Sprintf("%s: %s", msg, err))
	}
}

// AmqpChannel is the same as amqpConnect in boulder, but with even
// more aggressive error dropping
func AmqpChannel(url string) (ch *amqp.Channel) {
	conn, err := amqp.Dial(url)
	FailOnError(err, "Unable to connect to AMQP server")

	ch, err = conn.Channel()
	FailOnError(err, "Unable to establish channel to AMQP server")
	return
}

// RunForever starts the server and wait around
func RunForever(server *rpc.AmqpRPCServer) {
	forever := make(chan bool)
	server.Start()
	fmt.Fprintf(os.Stderr, "Server running...\n")
	<-forever
}

// RunUntilSignaled starts the server and run until we get something on closeChan
func RunUntilSignaled(logger *blog.AuditLogger, server *rpc.AmqpRPCServer, closeChan chan *amqp.Error) {
	server.Start()
	fmt.Fprintf(os.Stderr, "Server running...\n")

	// Block until channel closes
	err := <-closeChan

	logger.Warning(fmt.Sprintf("AMQP Channel closed, will reconnect in 5 seconds: [%s]", err))
	time.Sleep(time.Second * 5)
	logger.Warning("Reconnecting to AMQP...")
}

func ProfileCmd(profileName string, stats statsd.Statter) {
	for {
		var memoryStats runtime.MemStats
		runtime.ReadMemStats(&memoryStats)

		stats.Gauge(fmt.Sprintf("Gostats.%s.Goroutines", profileName), int64(runtime.NumGoroutine()), 1.0)

		stats.Gauge(fmt.Sprintf("Gostats.%s.Heap.Objects", profileName), int64(memoryStats.HeapObjects), 1.0)
		stats.Gauge(fmt.Sprintf("Gostats.%s.Heap.Idle", profileName), int64(memoryStats.HeapIdle), 1.0)
		stats.Gauge(fmt.Sprintf("Gostats.%s.Heap.InUse", profileName), int64(memoryStats.HeapInuse), 1.0)
		stats.Gauge(fmt.Sprintf("Gostats.%s.Heap.Released", profileName), int64(memoryStats.HeapReleased), 1.0)

		gcPauseAvg := int64(memoryStats.PauseTotalNs) / int64(len(memoryStats.PauseNs))

		stats.Timing(fmt.Sprintf("Gostats.%s.Gc.PauseAvg", profileName), gcPauseAvg, 1.0)
		stats.Gauge(fmt.Sprintf("Gostats.%s.Gc.NextAt", profileName), int64(memoryStats.NextGC), 1.0)

		time.Sleep(time.Second)
	}
}

func LoadCert(path string) (cert []byte, err error) {
	if path == "" {
		err = errors.New("Issuer certificate was not provided in config.")
		return
	}
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		err = errors.New("Invalid certificate value returned")
		return
	}

	cert = block.Bytes
	return
}
