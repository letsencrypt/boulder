package notmain

import (
	"context"
	"flag"
	"os"

	"github.com/letsencrypt/boulder/cmd"
	vaCommon "github.com/letsencrypt/boulder/cmd/boulder-va"
	"github.com/letsencrypt/boulder/features"
	vacfg "github.com/letsencrypt/boulder/va/config"
)

type Config struct {
	RVA struct {
		vacfg.Common
		TLSClient cmd.TLSConfig
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

	features.Set(c.RVA.Features)

	if *grpcAddr != "" {
		c.RVA.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.RVA.DebugAddr = *debugAddr
	}

	scope, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, c.RVA.DebugAddr)
	defer oTelShutdown(context.Background())
	logger.Info(cmd.VersionString())

	servers, err := vaCommon.SetupServerResolvers(c.RVA.DNSStaticResolvers, c.RVA.DNSProvider)
	if err != nil {
		cmd.Fail(err.Error())
	}
	defer servers.Stop()

	tlsServerConfig, err := c.RVA.TLS.Load(scope)
	cmd.FailOnError(err, "tlsConfig config")
	tlsClientConfig, err := c.RVA.TLSClient.Load(scope)
	cmd.FailOnError(err, "tlsConfig config")

	if c.RVA.DNSTimeout.Duration == 0 {
		cmd.Fail("'dnsTimeout' is required")
	}
	clk := cmd.Clock()
	resolver := vaCommon.SetupClientResolver(c.RVA.DNSTimeout.Duration, servers, scope, clk, c.RVA.DNSTries, logger, tlsClientConfig, c.RVA.DNSAllowLoopbackAddresses)

	start, err := vaCommon.SetupNewVAImplAndStartServer(resolver, nil, 0, c.RVA.UserAgent, c.RVA.IssuerDomain, scope, clk, logger, c.RVA.AccountURIPrefixes, c.RVA.GRPC, tlsServerConfig)
	if err != nil {
		cmd.Fail(err.Error())
	}
	cmd.FailOnError(start(), "VA gRPC service failed")
}

func init() {
	cmd.RegisterCommand("boulder-rva", main, &cmd.ConfigValidator{Config: &Config{}})
}
