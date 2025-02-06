package notmain

import (
	"context"
	"flag"
	"os"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/email"
	emailpb "github.com/letsencrypt/boulder/email/proto"
	bgrpc "github.com/letsencrypt/boulder/grpc"
)

// Config holds the configuration for the email-exporter service.
type Config struct {
	EmailExporter struct {
		cmd.ServiceConfig

		// PardotBusinessUnit is the Pardot business unit to use.
		PardotBusinessUnit string `validate:"required"`

		// ClientId is the OAuth API client ID provided by Salesforce.
		ClientId cmd.PasswordConfig

		// ClientSecret is the OAuth API client secret provided by Salesforce.
		ClientSecret cmd.PasswordConfig

		// SalesforceBaseURL is the base URL for the Salesforce API. (e.g.,
		// "https://login.salesforce.com")
		SalesforceBaseURL string `validate:"required"`

		// PardotBaseURL is the base URL for the Pardot API. (e.g.,
		// "https://pi.pardot.com")
		PardotBaseURL string `validate:"required"`
	}
	Syslog        cmd.SyslogConfig
	OpenTelemetry cmd.OpenTelemetryConfig
}

func main() {
	configFile := flag.String("config", "", "Path to configuration file")
	grpcAddr := flag.String("addr", "", "gRPC listen address override")
	debugAddr := flag.String("debug-addr", "", "Debug server address override")
	flag.Parse()

	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c Config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	if *grpcAddr != "" {
		c.EmailExporter.ServiceConfig.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.EmailExporter.ServiceConfig.DebugAddr = *debugAddr
	}

	scope, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, c.EmailExporter.ServiceConfig.DebugAddr)
	defer oTelShutdown(context.Background())

	logger.Info(cmd.VersionString())

	clk := cmd.Clock()
	clientId, err := c.EmailExporter.ClientId.Pass()
	cmd.FailOnError(err, "Loading client ID")
	clientSecret, err := c.EmailExporter.ClientSecret.Pass()
	cmd.FailOnError(err, "Loading client secret")

	pardotClient, err := email.NewPardotClient(
		clk,
		c.EmailExporter.PardotBusinessUnit,
		clientId,
		clientSecret,
		c.EmailExporter.SalesforceBaseURL,
		c.EmailExporter.PardotBaseURL,
	)
	cmd.FailOnError(err, "Creating Pardot client")
	exporterServer := email.NewExporterImpl(pardotClient, scope, logger)

	daemonCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Begin asynchronous processing of the email queue.
	go exporterServer.Start(daemonCtx)

	tlsConfig, err := c.EmailExporter.TLS.Load(scope)
	cmd.FailOnError(err, "Loading TLS config")

	start, err := bgrpc.NewServer(c.EmailExporter.GRPC, logger).Add(
		&emailpb.Exporter_ServiceDesc, exporterServer).Build(tlsConfig, scope, clk)
	cmd.FailOnError(err, "Configuring gRPC server")

	// Start the gRPC service.
	cmd.FailOnError(start(), "email-exporter gRPC service failed to start")
}

func init() {
	cmd.RegisterCommand("email-exporter", main, &cmd.ConfigValidator{Config: &Config{}})
}
