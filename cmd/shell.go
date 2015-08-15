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
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/letsencrypt/boulder/ca"
	"github.com/letsencrypt/boulder/core"
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
		Server   string
		Insecure bool
		RA       Queue
		VA       Queue
		SA       Queue
		CA       Queue
		OCSP     Queue
		TLS      *TLSConfig
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
		DBConnect string
	}

	Mailer struct {
		Server   string
		Port     string
		Username string
		Password string

		DBConnect string

		CertLimit int
		NagTimes  []string
		// Path to a text/template email template
		EmailTemplate string

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	OCSPResponder struct {
		DBConnect     string
		Path          string
		ListenAddress string

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	OCSPUpdater struct {
		DBConnect       string
		MinTimeToExpiry string
		ResponseLimit   int

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	ExternalCertImporter struct {
		CertsToImportCSVFilename   string
		DomainsToImportCSVFilename string
		CertsToRemoveCSVFilename   string
		StatsdRate                 float32
	}

	PA struct {
		DBDriver  string
		DBConnect string
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
		fmt.Fprintf(os.Stderr, "%s: %s\n", msg, err)
		os.Exit(1)
	}
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
