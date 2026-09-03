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

	"github.com/letsencrypt/boulder/bs3"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/boulder/mtpublisher"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/trees/issuancelog"
)

type Config struct {
	MTPublisher struct {
		DB cmd.DBConfig

		DebugAddr string `validate:"omitempty,hostname_port"`

		// PollInterval is how often the publisher scans for checkpoints that
		// still lack a mirror cosignature.
		PollInterval config.Duration `validate:"required"`

		// LogID identifies the issuance log this publisher operates on. It must
		// match the mtca's.
		LogID issuancelog.ID `validate:"required"`

		// MTCACertFile holds the PEM-encoded certificate of the mtca, whose
		// ML-DSA-44 public key is used to reconstruct each checkpoint's signed
		// note from the database.
		MTCACertFile string `validate:"required"`

		// Mirror identifies the mirror this publisher submits to. Note: this is
		// temporary until we start loading support multiple mirrors sourced from
		// https://www.gstatic.com/mtcs/cosigners/v1/cosigners.json (schema:
		// https://www.gstatic.com/mtcs/cosigners/v1/cosigners_schema.json).
		Mirror struct {
			// ID is the mirror's ID (e.g. "32473.9").
			ID string `validate:"required"`

			// PublicKeyFile holds the mirror's PEM-encoded ML-DSA-44 public
			// key.
			PublicKeyFile string `validate:"required"`

			// BaseURL is the base URL of the mirror's tlog-mirror submission
			// endpoints (e.g. "http://localhost:4700").
			BaseURL string `validate:"required,url"`

			// Timeout bounds each request to the mirror.
			Timeout config.Duration `validate:"required"`
		}

		// S3 locates the source log's tile storage, which the publisher reads
		// entries and proof hashes from when submitting to the mirror.
		S3 bs3.Config `validate:"required"`
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

	s3c, err := bs3.FromConfig(c.MTPublisher.S3, logger)
	cmd.FailOnError(err, "Loading S3 config")

	caCert, err := issuance.LoadCertificate(c.MTPublisher.MTCACertFile)
	cmd.FailOnError(err, "Loading MTCA certificate")
	caPubKey, ok := caCert.PublicKey.(*mldsa.PublicKey)
	if !ok {
		cmd.Fail(fmt.Sprintf("MTCA certificate public key is %T, must be ML-DSA-44", caCert.PublicKey))
	}

	mirrorPubKey, err := loadMLDSAPublicKey(c.MTPublisher.Mirror.PublicKeyFile)
	cmd.FailOnError(err, "Loading mirror public key")

	mirror, err := mtpublisher.NewMirrorClient(c.MTPublisher.Mirror.BaseURL, mtpublisher.NewSource(s3c, c.MTPublisher.LogID.TilePrefix()), c.MTPublisher.Mirror.ID, mirrorPubKey, c.MTPublisher.Mirror.Timeout.Duration)
	cmd.FailOnError(err, "Creating mirror client")

	publisher, err := mtpublisher.New(dbMap, c.MTPublisher.PollInterval.Duration, c.MTPublisher.LogID, caPubKey, mirror, logger)
	cmd.FailOnError(err, "Failed to create MTPublisher")

	ctx, cancel := context.WithCancel(context.Background())
	go cmd.CatchSignals(cancel)
	publisher.Start(ctx)
}

func init() {
	cmd.RegisterCommand("boulder-mtpublisher", main, &cmd.ConfigValidator{Config: &Config{}})
}
