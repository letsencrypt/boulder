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

		// PerDayLimit is our daily limit as determined by the tier of our
		// Salesforce account. For more information, see:
		// https://developer.salesforce.com/docs/marketing/pardot/guide/overview.html?q=rate%20limits
		PerDayLimit float64 `validate:"required,min=1"`

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
	cmd.FailOnError(err, "Loading clientId")
	clientSecret, err := c.EmailExporter.ClientSecret.Pass()
	cmd.FailOnError(err, "Loading clientSecret")

	pardotClient, err := email.NewPardotClientImpl(
		clk,
		c.EmailExporter.PardotBusinessUnit,
		clientId,
		clientSecret,
		c.EmailExporter.SalesforceBaseURL,
		c.EmailExporter.PardotBaseURL,
	)
	cmd.FailOnError(err, "Creating Pardot API client")
	exporterServer := email.NewExporterImpl(pardotClient, c.EmailExporter.PerDayLimit, scope, logger)

	tlsConfig, err := c.EmailExporter.TLS.Load(scope)
	cmd.FailOnError(err, "Loading email-exporter TLS config")

	daemonCtx, shutdownExporterServer := context.WithCancel(context.Background())
	go exporterServer.Start(daemonCtx)

	start, err := bgrpc.NewServer(c.EmailExporter.GRPC, logger).Add(
		&emailpb.Exporter_ServiceDesc, exporterServer).Build(tlsConfig, scope, clk)
	cmd.FailOnError(err, "Configuring email-exporter gRPC server")

	err = start()
	shutdownExporterServer()
	exporterServer.Drain()
	cmd.FailOnError(err, "email-exporter gRPC service failed to start")
}

func init() {
	cmd.RegisterCommand("email-exporter", main, &cmd.ConfigValidator{Config: &Config{}})
}
