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

		// MirrorID identifies the cosigner this publisher writes alongside each
		// cosignature (e.g. "32473.9").
		MirrorID string `validate:"required"`

		// Mirror configures the tlog-mirror this publisher submits to and the
		// source log it mirrors to obtain the mirror's cosignature.
		Mirror struct {
			// BaseURL is the mirror's tlog-mirror submission base URL.
			BaseURL string `validate:"required,url"`
			// Name is the mirror cosigner's key name.
			Name string `validate:"required"`
			// VerifierKeyFile is the path to a file holding the base64 of the
			// mirror's ML-DSA-44 public key, used to validate its cosignatures
			// (configured out of band; there is no endpoint to fetch it).
			VerifierKeyFile string `validate:"required"`
			// SourceOrigin is the origin of the source log.
			SourceOrigin string `validate:"required"`
			// SourceVerifierKey is a c2sp.org/signed-note verifier key for the
			// source log's checkpoint signature.
			SourceVerifierKey string `validate:"required"`
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

	verifierKey, err := os.ReadFile(c.MTPublisher.Mirror.VerifierKeyFile)
	cmd.FailOnError(err, "Reading mirror verifier key file")

	// Load the AWS config from just the configured files, so it never reads from
	// the homedir or other default locations. MinIO needs path-style addressing.
	awsConfig, err := awsconfig.LoadDefaultConfig(
		context.Background(),
		awsconfig.WithSharedConfigFiles([]string{c.MTPublisher.Mirror.AWSConfigFile}),
		awsconfig.WithSharedCredentialsFiles([]string{c.MTPublisher.Mirror.AWSCredsFile}),
		awsconfig.WithHTTPClient(new(http.Client)),
	)
	cmd.FailOnError(err, "Loading AWS config")
	s3Client := awss3.NewFromConfig(awsConfig,
		awss3.WithEndpointResolver(awss3.EndpointResolverFromURL(c.MTPublisher.Mirror.S3Endpoint)),
		func(o *awss3.Options) { o.UsePathStyle = true },
	)
	srcBackend := s3.New(s3Client, c.MTPublisher.Mirror.S3Bucket)

	publisher, err := mtpublisher.New(dbMap, c.MTPublisher.PollInterval.Duration, c.MTPublisher.MTCLogID, c.MTPublisher.MirrorID,
		mtpublisher.MirrorConfig{
			BaseURL:           c.MTPublisher.Mirror.BaseURL,
			Name:              c.MTPublisher.Mirror.Name,
			VerifierKey:       strings.TrimSpace(string(verifierKey)),
			SourceOrigin:      c.MTPublisher.Mirror.SourceOrigin,
			SourceVerifierKey: c.MTPublisher.Mirror.SourceVerifierKey,
		},
		srcBackend,
		clk, logger)
	cmd.FailOnError(err, "Failed to create MTPublisher")

	ctx, cancel := context.WithCancel(context.Background())
	go cmd.CatchSignals(cancel)
	publisher.Start(ctx)
}

func init() {
	cmd.RegisterCommand("boulder-mtpublisher", main, &cmd.ConfigValidator{Config: &Config{}})
}
