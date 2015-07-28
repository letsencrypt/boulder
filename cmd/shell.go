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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"
	"github.com/letsencrypt/boulder/ca"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/core"
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
		RA     Queue
		VA     Queue
		SA     Queue
		CA     Queue
		OCSP   Queue
		SSL    *SSLConfig
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

	VA struct {
		DNSResolver string
		DNSTimeout  string
	}

	SQL struct {
		CreateTables bool
		SQLDebug     bool
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

	Revoker struct {
		DBDriver string
		DBName   string
	}

	Mail struct {
		Server   string
		Port     string
		Username string
		Password string
	}

	OCSPResponder struct {
		DBDriver      string
		DBName        string
		Path          string
		ListenAddress string
	}

	OCSPUpdater struct {
		DBDriver        string
		DBName          string
		MinTimeToExpiry string
		ResponseLimit   int
	}

	ExternalCertImporter struct {
		CertsToImportCSVFilename   string
		DomainsToImportCSVFilename string
		CertsToRemoveCSVFilename   string
	}

	Common struct {
		BaseURL string
		// Path to a PEM-encoded copy of the issuer certificate.
		IssuerCert string
		MaxKeySize int
		PolicyDB policy.Config
	}

	SubscriberAgreementURL string
}

// SSLConfig reprents certificates and a key for authenticated TLS.
type SSLConfig struct {
	CertFile   string
	KeyFile    string
	CACertFile *string // Optional
}

// Queue describes a queue name
type Queue struct {
	Server string
}

// AppShell contains CLI Metadata
type AppShell struct {
	Action func(Config)
	Config func(*cli.Context, Config) Config
	App    *cli.App
}

// NewAppShell creates a basic AppShell object containing CLI metadata
func NewAppShell(name string) (shell *AppShell) {
	app := cli.NewApp()

	app.Name = name
	app.Version = fmt.Sprintf("0.1.0 [%s]", core.GetBuildID())

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "config",
			Value:  "config.json",
			EnvVar: "BOULDER_CONFIG",
			Usage:  "Path to Config JSON",
		},
	}

	return &AppShell{App: app}
}

// Run begins the application context, reading config and passing
// control to the default commandline action.
func (as *AppShell) Run() {
	as.App.Action = func(c *cli.Context) {
		configFileName := c.GlobalString("config")
		configJSON, err := ioutil.ReadFile(configFileName)
		FailOnError(err, "Unable to read config file")

		var config Config
		err = json.Unmarshal(configJSON, &config)
		FailOnError(err, "Failed to read configuration")

		if as.Config != nil {
			config = as.Config(c, config)
		}

		as.Action(config)
	}

	err := as.App.Run(os.Args)
	FailOnError(err, "Failed to run application")
}

// VersionString produces a friendly Application version string
func (as *AppShell) VersionString() string {
	return fmt.Sprintf("Versions: %s=(%s %s) Golang=(%s) BuildHost=(%s)", as.App.Name, core.GetBuildID(), core.GetBuildTime(), runtime.Version(), core.GetBuildHost())
}

// FailOnError exits and prints an error message if we encountered a problem
func FailOnError(err error, msg string) {
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		fmt.Fprintf(os.Stderr, "%s: %s", msg, err)
		os.Exit(1)
	}
}

// AmqpChannel is the same as amqpConnect in boulder, but with even
// more aggressive error dropping
func AmqpChannel(conf Config) (*amqp.Channel, error) {
	var conn *amqp.Connection

	if conf.AMQP.SSL != nil {
		if strings.HasPrefix(conf.AMQP.Server, "amqps") == false {
			err := fmt.Errorf("SSL configuration provided, but not using an AMQPS URL")
			return nil, err
		}

		cfg := new(tls.Config)

		cert, err := tls.LoadX509KeyPair(conf.AMQP.SSL.CertFile, conf.AMQP.SSL.KeyFile)
		if err != nil {
			err = fmt.Errorf("Could not load Client Certificates: %s", err)
			return nil, err
		}
		cfg.Certificates = append(cfg.Certificates, cert)

		if conf.AMQP.SSL.CACertFile != nil {
			cfg.RootCAs = x509.NewCertPool()

			ca, err := ioutil.ReadFile(*conf.AMQP.SSL.CACertFile)
			if err != nil {
				err = fmt.Errorf("Could not load CA Certificate: %s", err)
				return nil, err
			}
			cfg.RootCAs.AppendCertsFromPEM(ca)
		}

		conn, err = amqp.DialTLS(conf.AMQP.Server, cfg)
		if err != nil {
			return nil, err
		}

		return conn.Channel()
	}

	// Configuration did not specify SSL options
	conn, err := amqp.Dial(conf.AMQP.Server)
	if err != nil {
		return nil, err
	}

	return conn.Channel()
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

// ProfileCmd runs forever, sending Go statistics to StatsD.
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

// LoadCert loads a PEM-formatted certificate from the provided path, returning
// it as a byte array, or an error if it couldn't be decoded.
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
