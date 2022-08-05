package notmain

import (
	"context"
	"flag"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	awsl "github.com/aws/smithy-go/logging"
	"github.com/honeycombio/beeline-go"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/crl/storer"
	cspb "github.com/letsencrypt/boulder/crl/storer/proto"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
)

type Config struct {
	CRLStorer struct {
		cmd.ServiceConfig

		// IssuerCerts is a list of paths to issuer certificates on disk. These will
		// be used to validate the CRLs received by this service before uploading
		// them.
		IssuerCerts []string

		// S3Endpoint is the URL at which the S3-API-compatible object storage
		// service can be reached. This can be used to point to a non-Amazon storage
		// service, or to point to a fake service for testing. It should be left
		// blank by default.
		S3Endpoint string
		// S3Region is the AWS Region (e.g. us-west-1) that uploads should go to.
		S3Region string
		// S3Bucket is the AWS Bucket that uploads should go to. Must be created
		// (and have appropriate permissions set) beforehand.
		S3Bucket string
		// S3CredsFile is the path to a file on disk containing AWS credentials.
		// The format of the credentials file is specified at
		// https://docs.aws.amazon.com/sdkref/latest/guide/file-format.html.
		S3CredsFile string

		Features map[string]bool
	}

	Syslog  cmd.SyslogConfig
	Beeline cmd.BeelineConfig
}

// awsLogger implements the github.com/aws/smithy-go/logging.Logger interface.
type awsLogger struct {
	blog.Logger
}

func (log awsLogger) Logf(c awsl.Classification, format string, v ...interface{}) {
	switch c {
	case awsl.Debug:
		log.Debugf(format, v...)
	case awsl.Warn:
		log.Warningf(format, v...)
	}
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c Config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	err = features.Set(c.CRLStorer.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	tlsConfig, err := c.CRLStorer.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.CRLStorer.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())
	clk := cmd.Clock()

	bc, err := c.Beeline.Load()
	cmd.FailOnError(err, "Failed to load Beeline config")
	beeline.Init(bc)
	defer beeline.Close()

	issuers := make([]*issuance.Certificate, 0, len(c.CRLStorer.IssuerCerts))
	for _, filepath := range c.CRLStorer.IssuerCerts {
		cert, err := issuance.LoadCertificate(filepath)
		cmd.FailOnError(err, "Failed to load issuer cert")
		issuers = append(issuers, cert)
	}

	// Load the "default" AWS configuration, but override the set of config files
	// it reads from to be the empty set, and override the set of credentials
	// files it reads from to be just the one file specified in the Config. This
	// helps stop us from accidentally loading unexpected or undesired config.
	// Note that it *will* still load configuration from environment variables.
	awsConfig, err := config.LoadDefaultConfig(
		context.Background(),
		config.WithSharedConfigFiles([]string{}),
		config.WithSharedCredentialsFiles([]string{c.CRLStorer.S3CredsFile}),
		config.WithRegion(c.CRLStorer.S3Region),
		config.WithHTTPClient(new(http.Client)),
		config.WithLogger(awsLogger{logger}),
		config.WithClientLogMode(aws.LogRequestEventMessage|aws.LogResponseEventMessage),
	)
	cmd.FailOnError(err, "Failed to load AWS config")

	s3opts := make([]func(*s3.Options), 0)
	if c.CRLStorer.S3Endpoint != "" {
		s3opts = append(
			s3opts,
			s3.WithEndpointResolver(s3.EndpointResolverFromURL(c.CRLStorer.S3Endpoint)),
			func(o *s3.Options) { o.UsePathStyle = true },
		)
	}
	s3client := s3.NewFromConfig(awsConfig, s3opts...)

	csi, err := storer.New(issuers, s3client, c.CRLStorer.S3Bucket, scope, logger, clk)
	cmd.FailOnError(err, "Failed to create CRLStorer impl")

	serverMetrics := bgrpc.NewServerMetrics(scope)
	grpcSrv, listener, err := bgrpc.NewServer(c.CRLStorer.GRPC, tlsConfig, serverMetrics, clk)
	cmd.FailOnError(err, "Unable to setup CRLStorer gRPC server")
	cspb.RegisterCRLStorerServer(grpcSrv, csi)
	hs := health.NewServer()
	healthpb.RegisterHealthServer(grpcSrv, hs)

	go cmd.CatchSignals(logger, func() {
		hs.Shutdown()
		grpcSrv.GracefulStop()
	})

	err = cmd.FilterShutdownErrors(grpcSrv.Serve(listener))
	cmd.FailOnError(err, "CRLStorer gRPC service failed")
}

func init() {
	cmd.RegisterCommand("crl-storer", main)
}
