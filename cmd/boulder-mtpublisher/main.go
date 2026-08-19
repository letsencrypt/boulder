//go:build go1.27

package notmain

import (
	"context"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/mtpublisher"
	"github.com/letsencrypt/boulder/privatekey"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/trees/issuancelog"
)

type Config struct {
	MTPublisher struct {
		DB cmd.DBConfig

		DebugAddr string `validate:"omitempty,hostname_port"`

		// PollInterval is how often the stub scans for checkpoints that still
		// lack a mirror cosignature.
		PollInterval config.Duration `validate:"required"`

		// LogID identifies the issuance log this publisher operates on. It must
		// match the mtca's.
		LogID issuancelog.ID `validate:"required"`

		// MirrorID identifies the cosigner this publisher writes alongside each
		// cosignature (e.g. "32473.9").
		MirrorID string `validate:"required"`

		// MirrorPublicKeyFile holds the PEM-encoded ML-DSA-44 public key used
		// to verify cosignatures.
		MirrorPublicKeyFile string `validate:"required"`

		// MirrorKeyFile holds the PEM-encoded ML-DSA-44 private key used to
		// cosign checkpoints.
		MirrorKeyFile string `validate:"required"`
	}
	Syslog        cmd.SyslogConfig
	OpenTelemetry cmd.OpenTelemetryConfig
}

// loadMLDSAPublicKey reads a PEM-encoded PKIX ML-DSA-44 public key.
func loadMLDSAPublicKey(filename string) (*mldsa.PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("no PUBLIC KEY PEM block in %s", filename)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pubKey, ok := parsed.(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key in %s is %T, must be ML-DSA-44", filename, parsed)
	}
	return pubKey, nil
}

func main() {
	debugAddr := flag.String("debug-addr", "", "Debug server address override")
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c Config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	if *debugAddr != "" {
		c.MTPublisher.DebugAddr = *debugAddr
	}

	scope, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, c.MTPublisher.DebugAddr)
	defer oTelShutdown(context.Background())
	cmd.LogStartup(logger)

	dbMap, err := sa.InitWrappedDb(c.MTPublisher.DB, scope, logger)
	cmd.FailOnError(err, "While initializing dbMap")

	signer, _, err := privatekey.Load(c.MTPublisher.MirrorKeyFile)
	cmd.FailOnError(err, "Loading cosigner key")
	pubKey, err := loadMLDSAPublicKey(c.MTPublisher.MirrorPublicKeyFile)
	cmd.FailOnError(err, "Loading cosigner public key")

	publisher, err := mtpublisher.New(dbMap, c.MTPublisher.PollInterval.Duration, c.MTPublisher.LogID, c.MTPublisher.MirrorID, signer, pubKey, logger)
	cmd.FailOnError(err, "Failed to create MTPublisher stub")

	ctx, cancel := context.WithCancel(context.Background())
	go cmd.CatchSignals(cancel)
	publisher.Start(ctx)
}

func init() {
	cmd.RegisterCommand("boulder-mtpublisher", main, &cmd.ConfigValidator{Config: &Config{}})
}
