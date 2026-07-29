package notmain

import (
	"context"
	"flag"
	"os"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/bs3"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/crl/storer"
	cspb "github.com/letsencrypt/boulder/crl/storer/proto"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/issuance"
)

type Config struct {
	CRLStorer struct {
		cmd.ServiceConfig

		// IssuerCerts is a list of paths to issuer certificates on disk. These will
		// be used to validate the CRLs received by this service before uploading
		// them.
		IssuerCerts []string `validate:"min=1,dive,required"`

		// Storage config. Embedded so the fields can go at the top level.
		bs3.Config

		Features features.Config
	}

	Syslog        cmd.SyslogConfig
	OpenTelemetry cmd.OpenTelemetryConfig
}

func main() {
	grpcAddr := flag.String("addr", "", "gRPC listen address override")
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

	features.Set(c.CRLStorer.Features)

	if *grpcAddr != "" {
		c.CRLStorer.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.CRLStorer.DebugAddr = *debugAddr
	}

	scope, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, c.CRLStorer.DebugAddr)
	defer oTelShutdown(context.Background())
	cmd.LogStartup(logger)
	clk := clock.New()

	tlsConfig, err := c.CRLStorer.TLS.Load(scope)
	cmd.FailOnError(err, "TLS config")

	issuers := make([]*issuance.Certificate, 0, len(c.CRLStorer.IssuerCerts))
	for _, filepath := range c.CRLStorer.IssuerCerts {
		cert, err := issuance.LoadCertificate(filepath)
		cmd.FailOnError(err, "Failed to load issuer cert")
		issuers = append(issuers, cert)
	}

	s3client, err := bs3.FromConfig(c.CRLStorer.Config, logger)
	cmd.FailOnError(err, "Initializing S3 client")

	csi, err := storer.New(issuers, s3client, scope, logger, clk)
	cmd.FailOnError(err, "Failed to create CRLStorer impl")

	start, err := bgrpc.NewServer(c.CRLStorer.GRPC, logger).Add(
		&cspb.CRLStorer_ServiceDesc, csi).Build(tlsConfig, scope, clk)
	cmd.FailOnError(err, "Unable to setup CRLStorer gRPC server")

	cmd.FailOnError(start(), "CRLStorer gRPC service failed")
}

func init() {
	cmd.RegisterCommand("crl-storer", main, &cmd.ConfigValidator{Config: &Config{}})
}
