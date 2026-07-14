package notmain

import (
	"context"
	"flag"
	"net/http"
	"os"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/mtpublisher"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/trees/tilestore/s3"
)

type Config struct {
	MTPublisher struct {
		DB cmd.DBConfig

		DebugAddr string `validate:"omitempty,hostname_port"`

		// PollInterval is how often the stub scans for checkpoints that still
		// lack a mirror cosignature.
		PollInterval config.Duration `validate:"required"`

		// MTCLogID is the log this MTPublisher operates on (e.g.
		// "44947.4.1.0.44"). Used as a guard on the `mtcLogID` column of the
		// connected checkpoints table.
		MTCLogID string `validate:"required"`

		// Quorum is how many tier-1 mirrors must commit a checkpoint before
		// its cosignature is recorded.
		Quorum int `validate:"min=1"`

		// Source locates and authenticates the source log this publisher
		// mirrors.
		Source struct {
			// Origin is the source log's checkpoint origin.
			Origin string `validate:"required"`
			// VerifierKey is a c2sp.org/signed-note verifier key for the
			// source log's checkpoint signature.
			VerifierKey string `validate:"required"`
			// S3Endpoint is the URL of the S3-compatible object store (MinIO)
			// holding the source log's tiles.
			S3Endpoint string `validate:"required,url"`
			// S3Bucket is the bucket the source log's tiles live in.
			S3Bucket string `validate:"required"`
			// AWSConfigFile and AWSCredsFile are the AWS SDK shared config and
			// credentials files, holding the region and the access keys.
			AWSConfigFile string `validate:"required"`
			AWSCredsFile  string `validate:"required"`
		}

		// Mirrors configures the tlog-mirrors this publisher submits to.
		Mirrors []struct {
			// ID is the mirror's OID relative to 1.3.6.1.4.1 (e.g. "32473.9"),
			// recorded alongside the cosignature it contributes.
			ID string `validate:"required"`
			// BaseURL is the mirror's tlog-mirror submission base URL.
			BaseURL string `validate:"required,url"`
			// Name is the mirror cosigner's key name.
			Name string `validate:"required"`
			// VerifierKeyFile is the path to a file holding the base64 of the
			// mirror's ML-DSA-44 public key, used to validate its cosignatures
			// (configured out of band; there is no endpoint to fetch it).
			VerifierKeyFile string `validate:"required"`
			// Tier1 mirrors count toward the cosignature quorum. Tier-2
			// mirrors are kept up to date and monitored but never block.
			Tier1 bool
		} `validate:"min=1,dive"`
	}
	Syslog        cmd.SyslogConfig
	OpenTelemetry cmd.OpenTelemetryConfig
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
	clk := clock.New()

	dbMap, err := sa.InitWrappedDb(c.MTPublisher.DB, scope, logger)
	cmd.FailOnError(err, "While initializing dbMap")

	var mirrors []mtpublisher.MirrorConfig
	for _, mc := range c.MTPublisher.Mirrors {
		verifierKey, err := os.ReadFile(mc.VerifierKeyFile)
		cmd.FailOnError(err, "Reading mirror verifier key file")
		mirrors = append(mirrors, mtpublisher.MirrorConfig{
			ID:          mc.ID,
			BaseURL:     mc.BaseURL,
			Name:        mc.Name,
			VerifierKey: strings.TrimSpace(string(verifierKey)),
			Tier1:       mc.Tier1,
		})
	}

	// Load the AWS config from just the configured files, so it never reads from
	// the homedir or other default locations. MinIO needs path-style addressing.
	awsConfig, err := awsconfig.LoadDefaultConfig(
		context.Background(),
		awsconfig.WithSharedConfigFiles([]string{c.MTPublisher.Source.AWSConfigFile}),
		awsconfig.WithSharedCredentialsFiles([]string{c.MTPublisher.Source.AWSCredsFile}),
		awsconfig.WithHTTPClient(new(http.Client)),
	)
	cmd.FailOnError(err, "Loading AWS config")
	s3Client := awss3.NewFromConfig(awsConfig,
		awss3.WithEndpointResolver(awss3.EndpointResolverFromURL(c.MTPublisher.Source.S3Endpoint)),
		func(o *awss3.Options) { o.UsePathStyle = true },
	)
	srcBackend := s3.New(s3Client, c.MTPublisher.Source.S3Bucket)

	publisher, err := mtpublisher.New(dbMap, c.MTPublisher.PollInterval.Duration, c.MTPublisher.MTCLogID,
		mtpublisher.SourceConfig{
			Origin:      c.MTPublisher.Source.Origin,
			VerifierKey: c.MTPublisher.Source.VerifierKey,
		},
		mirrors, c.MTPublisher.Quorum,
		srcBackend, scope, clk, logger)
	cmd.FailOnError(err, "Failed to create MTPublisher")

	ctx, cancel := context.WithCancel(context.Background())
	go cmd.CatchSignals(cancel)
	publisher.Start(ctx)
}

func init() {
	cmd.RegisterCommand("boulder-mtpublisher", main, &cmd.ConfigValidator{Config: &Config{}})
}
