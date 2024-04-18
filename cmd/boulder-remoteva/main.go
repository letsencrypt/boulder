package notmain

import (
	"context"
	"flag"
	"os"
	"time"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/va"
	vacfg "github.com/letsencrypt/boulder/va/config"
	vapb "github.com/letsencrypt/boulder/va/proto"
)

type Config struct {
	RVA struct {
		vacfg.Shared
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

	if c.RVA.DNSTimeout.Duration == 0 {
		cmd.Fail("'dnsTimeout' is required")
	}
	dnsTries := c.RVA.DNSTries
	if dnsTries < 1 {
		dnsTries = 1
	}
	clk := cmd.Clock()

	var servers bdns.ServerProvider
	proto := "udp"
	if features.Get().DOH {
		proto = "tcp"
	}

	if len(c.RVA.DNSStaticResolvers) != 0 {
		servers, err = bdns.NewStaticProvider(c.RVA.DNSStaticResolvers)
		cmd.FailOnError(err, "Couldn't start static DNS server resolver")
	} else {
		servers, err = bdns.StartDynamicProvider(c.RVA.DNSProvider, 60*time.Second, proto)
		cmd.FailOnError(err, "Couldn't start dynamic DNS server resolver")
	}
	defer servers.Stop()

	tlsConfig, err := c.RVA.TLS.Load(scope)
	cmd.FailOnError(err, "tlsConfig config")

	var resolver bdns.Client
	if !c.RVA.DNSAllowLoopbackAddresses {
		resolver = bdns.New(
			c.RVA.DNSTimeout.Duration,
			servers,
			scope,
			clk,
			dnsTries,
			logger,
			tlsConfig)
	} else {
		resolver = bdns.NewTest(
			c.RVA.DNSTimeout.Duration,
			servers,
			scope,
			clk,
			dnsTries,
			logger,
			tlsConfig)
	}

	vai, err := va.NewValidationAuthorityImpl(
		resolver,
		nil, // A remote VA itself will not have remote VAs.
		0,   // MaxRemoteValidationFailures is intended for the primary VA only
		c.RVA.UserAgent,
		c.RVA.IssuerDomain,
		scope,
		clk,
		logger,
		c.RVA.AccountURIPrefixes)
	cmd.FailOnError(err, "Unable to create remote VA server")

	start, err := bgrpc.NewServer(c.RVA.GRPC, logger).Add(
		&vapb.VA_ServiceDesc, vai).Add(
		&vapb.CAA_ServiceDesc, vai).Build(tlsConfig, scope, clk)
	cmd.FailOnError(err, "Unable to setup remote VA gRPC server")

	cmd.FailOnError(start(), "remote VA gRPC service failed")
}

func init() {
	// TODO(#5294) After we have separate RVA and VA binaries deployed,
	// re-register boulder-remoteva2 as boulder-remoteva.
	cmd.RegisterCommand("boulder-remoteva2", main, &cmd.ConfigValidator{Config: &Config{}})
}
