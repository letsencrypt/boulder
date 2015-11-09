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
	_ "net/http/pprof" // HTTP performance profiling, added transparently to HTTP APIs
	"os"
	"runtime"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	cfsslConfig "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/config"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/publisher"
	"github.com/letsencrypt/boulder/va"
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
		Server            string
		Insecure          bool
		RA                Queue
		VA                Queue
		SA                Queue
		CA                Queue
		OCSP              Queue
		Publisher         Queue
		TLS               *TLSConfig
		ReconnectTimeouts struct {
			Base ConfigDuration
			Max  ConfigDuration
		}
	}

	WFE struct {
		BaseURL       string
		ListenAddress string

		AllowOrigins []string

		CertCacheDuration           string
		CertNoCacheExpirationWindow string
		IndexCacheDuration          string
		IssuerCacheDuration         string

		ShutdownStopTimeout string
		ShutdownKillTimeout string

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	CA CAConfig

	Monolith struct {
		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	RA struct {
		RateLimitPoliciesFilename string

		MaxConcurrentRPCServerRequests int64

		MaxContactsPerRegistration int

		// UseIsSafeDomain determines whether to call VA.IsSafeDomain
		UseIsSafeDomain bool // TODO(jmhodges): remove after va IsSafeDomain deploy

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	SA struct {
		DBConnect string

		MaxConcurrentRPCServerRequests int64

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	VA struct {
		UserAgent string

		PortConfig va.PortConfig

		MaxConcurrentRPCServerRequests int64

		GoogleSafeBrowsing *GoogleSafeBrowsingConfig

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	SQL struct {
		SQLDebug bool
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
		// How much earlier (than configured nag intervals) to
		// send reminders, to account for the expected delay
		// before the next expiration-mailer invocation.
		NagCheckInterval string
		// Path to a text/template email template
		EmailTemplate string

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	OCSPResponder struct {
		// Source indicates the source of pre-signed OCSP responses to be used. It
		// can be a DBConnect string or a file URL. The file URL style is used
		// when responding from a static file for intermediates and roots.
		Source string

		Path          string
		ListenAddress string
		// MaxAge is the max-age to set in the Cache-Controler response
		// header. It is a time.Duration formatted string.
		MaxAge ConfigDuration

		ShutdownStopTimeout string
		ShutdownKillTimeout string

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	OCSPUpdater OCSPUpdaterConfig

	Publisher struct {
		MaxConcurrentRPCServerRequests int64

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	ExternalCertImporter struct {
		CertsToImportCSVFilename   string
		DomainsToImportCSVFilename string
		CertsToRemoveCSVFilename   string
		StatsdRate                 float32
	}

	PA PAConfig

	Common struct {
		BaseURL string
		// Path to a PEM-encoded copy of the issuer certificate.
		IssuerCert string

		DNSResolver               string
		DNSTimeout                string
		DNSAllowLoopbackAddresses bool

		CT publisher.CTConfig
	}

	CertChecker struct {
		Workers             int
		ReportDirectoryPath string
		DBConnect           string
	}

	SubscriberAgreementURL string
}

// CAConfig structs have configuration information for the certificate
// authority, including database parameters as well as controls for
// issued certificates.
type CAConfig struct {
	Profile      string
	TestMode     bool
	DBConnect    string
	SerialPrefix int
	Key          KeyConfig
	// LifespanOCSP is how long OCSP responses are valid for; It should be longer
	// than the minTimeToExpiry field for the OCSP Updater.
	LifespanOCSP string
	// How long issued certificates are valid for, should match expiry field
	// in cfssl config.
	Expiry string
	// The maximum number of subjectAltNames in a single certificate
	MaxNames int
	CFSSL    cfsslConfig.Config

	MaxConcurrentRPCServerRequests int64

	HSMFaultTimeout ConfigDuration

	// DebugAddr is the address to run the /debug handlers on.
	DebugAddr string
}

// PAConfig specifies how a policy authority should connect to its
// database, and what policies it should enforce.
type PAConfig struct {
	DBConnect              string
	EnforcePolicyWhitelist bool
}

// KeyConfig should contain either a File path to a PEM-format private key,
// or a PKCS11Config defining how to load a module for an HSM.
type KeyConfig struct {
	File   string
	PKCS11 PKCS11Config
}

// PKCS11Config defines how to load a module for an HSM.
type PKCS11Config struct {
	Module          string
	TokenLabel      string
	PIN             string
	PrivateKeyLabel string
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

// OCSPUpdaterConfig provides the various window tick times and batch sizes needed
// for the OCSP (and SCT) updater
type OCSPUpdaterConfig struct {
	DBConnect string

	NewCertificateWindow     ConfigDuration
	OldOCSPWindow            ConfigDuration
	MissingSCTWindow         ConfigDuration
	RevokedCertificateWindow ConfigDuration

	NewCertificateBatchSize     int
	OldOCSPBatchSize            int
	MissingSCTBatchSize         int
	RevokedCertificateBatchSize int

	OCSPMinTimeToExpiry ConfigDuration
	OldestIssuedSCT     ConfigDuration

	AkamaiBaseURL           string
	AkamaiClientToken       string
	AkamaiClientSecret      string
	AkamaiAccessToken       string
	AkamaiPurgeRetries      int
	AkamaiPurgeRetryBackoff ConfigDuration

	SignFailureBackoffFactor float64
	SignFailureBackoffMax    ConfigDuration

	// DebugAddr is the address to run the /debug handlers on.
	DebugAddr string
}

// AppShell contains CLI Metadata
type AppShell struct {
	Action func(Config)
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
		logger := blog.GetAuditLogger()
		logger.Err(fmt.Sprintf("%s: %s", msg, err))
		fmt.Fprintf(os.Stderr, "%s: %s\n", msg, err)
		os.Exit(1)
	}
}

// ProfileCmd runs forever, sending Go runtime statistics to StatsD.
func ProfileCmd(profileName string, stats statsd.Statter) {
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
	log.Printf("booting debug server at %#v", addr)
	log.Println(http.Serve(ln, nil))
}

// ConfigDuration is just an alias for time.Duration that allows
// serialization to YAML as well as JSON.
type ConfigDuration struct {
	time.Duration
}

// ErrDurationMustBeString is returned when a non-string value is
// presented to be deserialized as a ConfigDuration
var ErrDurationMustBeString = errors.New("cannot JSON unmarshal something other than a string into a ConfigDuration")

// UnmarshalJSON parses a string into a ConfigDuration using
// time.ParseDuration.  If the input does not unmarshal as a
// string, then UnmarshalJSON returns ErrDurationMustBeString.
func (d *ConfigDuration) UnmarshalJSON(b []byte) error {
	s := ""
	err := json.Unmarshal(b, &s)
	if err != nil {
		if _, ok := err.(*json.UnmarshalTypeError); ok {
			return ErrDurationMustBeString
		}
		return err
	}
	dd, err := time.ParseDuration(s)
	d.Duration = dd
	return err
}

// MarshalJSON returns the string form of the duration, as a byte array.
func (d ConfigDuration) MarshalJSON() ([]byte, error) {
	return []byte(d.Duration.String()), nil
}

// UnmarshalYAML uses the same frmat as JSON, but is called by the YAML
// parser (vs. the JSON parser).
func (d *ConfigDuration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}

	d.Duration = dur
	return nil
}
