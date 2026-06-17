//go:build go1.27

package notmain

import (
	"context"
	"flag"
	"os"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/cmd"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/issuance"
	mtca "github.com/letsencrypt/boulder/mtca"
	mtcapb "github.com/letsencrypt/boulder/mtca/proto"
)

type Config struct {
	MTCA struct {
		cmd.ServiceConfig

		GRPCMTCA *cmd.GRPCServerConfig

		// Issuer holds the configuration for a single MTCA instance with a single mtcaID.
		// We run a separate process for each issuer.
		// TODO: the issuance package parses the CA certificate as a self-signed X.509
		// certificate, but per MTC draft, a CA SHOULD be represented by an RFC 9925
		// unsigned certificate: https://www.rfc-editor.org/rfc/rfc9925.html.
		Issuer issuance.IssuerConfig
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

	if *grpcAddr != "" {
		c.MTCA.GRPCMTCA.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.MTCA.DebugAddr = *debugAddr
	}

	scope, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, c.MTCA.DebugAddr)
	defer oTelShutdown(context.Background())
	cmd.LogStartup(logger)

	tlsConfig, err := c.MTCA.TLS.Load(scope)
	cmd.FailOnError(err, "Loading TLS config")

	clk := clock.New()

	issuer, err := issuance.LoadIssuer(c.MTCA.Issuer, clk)
	cmd.FailOnError(err, "Loading issuer")

	mtcaImpl := mtca.New(issuer)

	srv := bgrpc.NewServer(c.MTCA.GRPCMTCA, logger).Add(
		&mtcapb.MTCA_ServiceDesc, mtcaImpl)

	start, err := srv.Build(tlsConfig, scope, clk)
	cmd.FailOnError(err, "Unable to setup MTCA gRPC server")

	cmd.FailOnError(start(), "MTCA gRPC service failed")
}

func init() {
	cmd.RegisterCommand("boulder-mtca", main, &cmd.ConfigValidator{Config: &Config{}})
}
