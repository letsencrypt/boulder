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
	_ "expvar" // For DebugServer, below.
	"fmt"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/go-sql-driver/mysql"
	"io/ioutil"
	"log"
	"log/syslog"
	"net"
	"net/http"
	_ "net/http/pprof" // HTTP performance profiling, added transparently to HTTP APIs
	"os"
	"path"
	"runtime"
	"time"

	cfsslLog "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/log"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
)

// AppShell contains CLI Metadata
type AppShell struct {
	Action func(Config, metrics.Statter, *blog.AuditLogger)
	Config func(*cli.Context, Config) Config
	App    *cli.App
}

// Version returns a string representing the version of boulder running.
func Version() string {
	return fmt.Sprintf("0.1.0 [%s]", core.GetBuildID())
}

// NewAppShell creates a basic AppShell object containing CLI metadata
func NewAppShell(name, usage string) (shell *AppShell) {
	app := cli.NewApp()

	app.Name = name
	app.Usage = usage
	app.Version = Version()
	app.Author = "Boulder contributors"
	app.Email = "ca-dev@letsencrypt.org"

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

		// Provide default values for each service's AMQP config section.
		if config.WFE.AMQP == nil {
			config.WFE.AMQP = config.AMQP
		}
		if config.CA.AMQP == nil {
			config.CA.AMQP = config.AMQP
			if config.CA.AMQP != nil && config.AMQP.CA != nil {
				config.CA.AMQP.ServiceQueue = config.AMQP.CA.Server
			}
		}
		if config.RA.AMQP == nil {
			config.RA.AMQP = config.AMQP
			if config.RA.AMQP != nil && config.AMQP.RA != nil {
				config.RA.AMQP.ServiceQueue = config.AMQP.RA.Server
			}
		}
		if config.SA.AMQP == nil {
			config.SA.AMQP = config.AMQP
			if config.SA.AMQP != nil && config.AMQP.SA != nil {
				config.SA.AMQP.ServiceQueue = config.AMQP.SA.Server
			}
		}
		if config.VA.AMQP == nil {
			config.VA.AMQP = config.AMQP
			if config.VA.AMQP != nil && config.AMQP.VA != nil {
				config.VA.AMQP.ServiceQueue = config.AMQP.VA.Server
			}
		}
		if config.Mailer.AMQP == nil {
			config.Mailer.AMQP = config.AMQP
		}
		if config.OCSPUpdater.AMQP == nil {
			config.OCSPUpdater.AMQP = config.AMQP
		}
		if config.OCSPResponder.AMQP == nil {
			config.OCSPResponder.AMQP = config.AMQP
		}
		if config.Publisher.AMQP == nil {
			config.Publisher.AMQP = config.AMQP
			if config.Publisher.AMQP != nil && config.AMQP.Publisher != nil {
				config.Publisher.AMQP.ServiceQueue = config.AMQP.Publisher.Server
			}
		}

		stats, auditlogger := StatsAndLogging(config.Statsd, config.Syslog)
		auditlogger.Info(as.VersionString())

		// If as.Action generates a panic, this will log it to syslog.
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		as.Action(config, stats, auditlogger)
	}

	err := as.App.Run(os.Args)
	FailOnError(err, "Failed to run application")
}

// mysqlLogger proxies blog.AuditLogger to provide a Print(...) method.
type mysqlLogger struct {
	*blog.AuditLogger
}

func (m mysqlLogger) Print(v ...interface{}) {
	m.Err(fmt.Sprintf("[mysql] %s", fmt.Sprint(v...)))
}

// StatsAndLogging constructs a Statter and an AuditLogger based on its config
// parameters, and return them both. Crashes if any setup fails.
// Also sets the constructed AuditLogger as the default logger.
func StatsAndLogging(statConf StatsdConfig, logConf SyslogConfig) (metrics.Statter, *blog.AuditLogger) {
	stats, err := metrics.NewStatter(statConf.Server, statConf.Prefix)
	FailOnError(err, "Couldn't connect to statsd")

	tag := path.Base(os.Args[0])
	syslogger, err := syslog.Dial(
		logConf.Network,
		logConf.Server,
		syslog.LOG_INFO|syslog.LOG_LOCAL0, // default, overridden by log calls
		tag)
	FailOnError(err, "Could not connect to Syslog")
	level := int(syslog.LOG_DEBUG)
	if logConf.StdoutLevel != nil {
		level = *logConf.StdoutLevel
	}
	auditLogger, err := blog.NewAuditLogger(syslogger, stats, level)
	FailOnError(err, "Could not connect to Syslog")

	blog.SetAuditLogger(auditLogger)
	cfsslLog.SetLogger(auditLogger)
	mysql.SetLogger(mysqlLogger{auditLogger})

	return stats, auditLogger
}

// VersionString produces a friendly Application version string
func (as *AppShell) VersionString() string {
	return fmt.Sprintf("Versions: %s=(%s %s) Golang=(%s) BuildHost=(%s)", as.App.Name, core.GetBuildID(), core.GetBuildTime(), runtime.Version(), core.GetBuildHost())
}

// FailOnError exits and prints an error message if we encountered a problem
func FailOnError(err error, msg string) {
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		logger := blog.GetAuditLogger()
		logger.Err(fmt.Sprintf("%s: %s", msg, err))
		fmt.Fprintf(os.Stderr, "%s: %s\n", msg, err)
		os.Exit(1)
	}
}

// ProfileCmd runs forever, sending Go runtime statistics to StatsD.
func ProfileCmd(profileName string, stats metrics.Statter) {
	var memoryStats runtime.MemStats
	prevNumGC := int64(0)
	c := time.Tick(1 * time.Second)
	for range c {
		runtime.ReadMemStats(&memoryStats)

		// Gather goroutine count
		stats.Gauge(fmt.Sprintf("%s.Gostats.Goroutines", profileName), int64(runtime.NumGoroutine()), 1.0)

		// Gather various heap metrics
		stats.Gauge(fmt.Sprintf("%s.Gostats.Heap.Alloc", profileName), int64(memoryStats.HeapAlloc), 1.0)
		stats.Gauge(fmt.Sprintf("%s.Gostats.Heap.Objects", profileName), int64(memoryStats.HeapObjects), 1.0)
		stats.Gauge(fmt.Sprintf("%s.Gostats.Heap.Idle", profileName), int64(memoryStats.HeapIdle), 1.0)
		stats.Gauge(fmt.Sprintf("%s.Gostats.Heap.InUse", profileName), int64(memoryStats.HeapInuse), 1.0)
		stats.Gauge(fmt.Sprintf("%s.Gostats.Heap.Released", profileName), int64(memoryStats.HeapReleased), 1.0)

		// Gather various GC related metrics
		if memoryStats.NumGC > 0 {
			totalRecentGC := uint64(0)
			realBufSize := uint32(256)
			if memoryStats.NumGC < 256 {
				realBufSize = memoryStats.NumGC
			}
			for _, pause := range memoryStats.PauseNs {
				totalRecentGC += pause
			}
			gcPauseAvg := totalRecentGC / uint64(realBufSize)
			lastGC := memoryStats.PauseNs[(memoryStats.NumGC+255)%256]
			stats.Timing(fmt.Sprintf("%s.Gostats.Gc.PauseAvg", profileName), int64(gcPauseAvg), 1.0)
			stats.Gauge(fmt.Sprintf("%s.Gostats.Gc.LastPause", profileName), int64(lastGC), 1.0)
		}
		stats.Gauge(fmt.Sprintf("%s.Gostats.Gc.NextAt", profileName), int64(memoryStats.NextGC), 1.0)
		// Send both a counter and a gauge here we can much more easily observe
		// the GC rate (versus the raw number of GCs) in graphing tools that don't
		// like deltas
		stats.Gauge(fmt.Sprintf("%s.Gostats.Gc.Count", profileName), int64(memoryStats.NumGC), 1.0)
		gcInc := int64(memoryStats.NumGC) - prevNumGC
		stats.Inc(fmt.Sprintf("%s.Gostats.Gc.Rate", profileName), gcInc, 1.0)
		prevNumGC += gcInc
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

// DebugServer starts a server to receive debug information.  Typical
// usage is to start it in a goroutine, configured with an address
// from the appropriate configuration object:
//
//   go cmd.DebugServer(c.XA.DebugAddr)
func DebugServer(addr string) {
	if addr == "" {
		log.Fatalf("unable to boot debug server because no address was given for it. Set debugAddr.")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("unable to boot debug server on %#v", addr)
	}
	http.Serve(ln, nil)
}
