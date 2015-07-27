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
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"
	"github.com/letsencrypt/boulder/ca"
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
	ActivityMonitor struct {
		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	// General
	AMQP struct {
		Server string
		RA     Queue
		VA     Queue
		SA     Queue
		CA     Queue
		OCSP   Queue
		TLS    *TLSConfig
	}

	WFE struct {
		BaseURL       string
		ListenAddress string

		CertCacheDuration           string
		CertNoCacheExpirationWindow string
		IndexCacheDuration          string
		IssuerCacheDuration         string

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	CA ca.Config

	Monolith struct {
		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	RA struct {
		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	SA struct {
		DBDriver  string
		DBConnect string

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	VA struct {
		UserAgent string

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
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
		DBDriver  string
		DBConnect string
	}

	Mailer struct {
		Server   string
		Port     string
		Username string
		Password string

		DBDriver  string
		DBConnect string

		CertLimit int
		NagTimes  []string
		// Path to a text/template email template
		EmailTemplate string

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	OCSPResponder struct {
		DBDriver      string
		DBConnect     string
		Path          string
		ListenAddress string

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	OCSPUpdater struct {
		DBDriver        string
		DBConnect       string
		MinTimeToExpiry string
		ResponseLimit   int

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	Common struct {
		BaseURL string
		// Path to a PEM-encoded copy of the issuer certificate.
		IssuerCert string
		MaxKeySize int

		DNSResolver string
		DNSTimeout  string
	}

	SubscriberAgreementURL string
}

// TLSConfig reprents certificates and a key for authenticated TLS.
type TLSConfig struct {
	CertFile   *string
	KeyFile    *string
	CACertFile *string
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
	var err error

	log := blog.GetAuditLogger()

	if conf.AMQP.TLS == nil {
		// Configuration did not specify TLS options, but Dial will
		// use TLS anyway if the URL scheme is "amqps"
		conn, err = amqp.Dial(conf.AMQP.Server)

	} else {
		// They provided TLS options, so let's load them.
		log.Info("AMQPS: Loading TLS Options.")

		if strings.HasPrefix(conf.AMQP.Server, "amqps") == false {
			err = fmt.Errorf("AMQPS: TLS configuration provided, but not using an AMQPS URL")
			return nil, err
		}

		cfg := new(tls.Config)

		// If the configuration specified a certificate (or key), load them
		if conf.AMQP.TLS.CertFile != nil || conf.AMQP.TLS.KeyFile != nil {
			// But they have to give both.
			if conf.AMQP.TLS.CertFile == nil || conf.AMQP.TLS.KeyFile == nil {
				err = fmt.Errorf("AMQPS: You must set both of the configuration values AMQP.TLS.KeyFile and AMQP.TLS.CertFile")
				return nil, err
			}

			cert, err := tls.LoadX509KeyPair(*conf.AMQP.TLS.CertFile, *conf.AMQP.TLS.KeyFile)
			if err != nil {
				err = fmt.Errorf("AMQPS: Could not load Client Certificate or Key: %s", err)
				return nil, err
			}

			log.Info("AMQPS: Configured client certificate for AMQPS.")
			cfg.Certificates = append(cfg.Certificates, cert)
		}

		// If the configuration specified a CA certificate, make it the only
		// available root.
		if conf.AMQP.TLS.CACertFile != nil {
			cfg.RootCAs = x509.NewCertPool()

			ca, err := ioutil.ReadFile(*conf.AMQP.TLS.CACertFile)
			if err != nil {
				err = fmt.Errorf("AMQPS: Could not load CA Certificate: %s", err)
				return nil, err
			}
			cfg.RootCAs.AppendCertsFromPEM(ca)
			log.Info("AMQPS: Configured CA certificate for AMQPS.")
		}

		conn, err = amqp.DialTLS(conf.AMQP.Server, cfg)
	}

	if err != nil {
		return nil, err
	}

	err = rpc.AMQPDeclareExchange(conn)
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

func DebugServer(addr string) {
	if addr == "" {
		log.Fatalf("unable to boot debug server because no address was given for it. Set debugAddr.")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("unable to boot debug server on %#v", addr)
	}
	log.Printf("booting debug server at %#v", addr)
	log.Println(http.Serve(ln, nil))
}
