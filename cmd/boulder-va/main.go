package notmain

import (
	"context"
	"flag"
	"os"
	"time"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/va"
	vapb "github.com/letsencrypt/boulder/va/proto"
)

type Config struct {
	VA struct {
		cmd.ServiceConfig

		UserAgent string

		IssuerDomain string

		// DNSTries is the number of times to try a DNS query (that has a temporary error)
		// before giving up. May be short-circuited by deadlines. A zero value
		// will be turned into 1.
		DNSTries                  int
		DNSProvider               *cmd.DNSProvider `validate:"required"`
		DNSTimeout                config.Duration  `validate:"required"`
		DNSAllowLoopbackAddresses bool

		RemoteVAs                   []cmd.GRPCClientConfig `validate:"omitempty,dive"`
		MaxRemoteValidationFailures int

		Features map[string]bool

		AccountURIPrefixes []string `validate:"min=1,dive,required,url"`
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

	err = features.Set(c.VA.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	if *grpcAddr != "" {
		c.VA.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.VA.DebugAddr = *debugAddr
	}

	scope, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, c.VA.DebugAddr)
	defer oTelShutdown(context.Background())
	logger.Info(cmd.VersionString())

	if c.VA.DNSTimeout.Duration == 0 {
		cmd.Fail("'dnsTimeout' is required")
	}
	dnsTries := c.VA.DNSTries
	if dnsTries < 1 {
		dnsTries = 1
	}
	clk := cmd.Clock()

	if c.VA.DNSProvider == nil {
		cmd.Fail("Must specify dnsProvider")
	}

	var servers bdns.ServerProvider
	servers, err = bdns.StartDynamicProvider(c.VA.DNSProvider, 60*time.Second)
	cmd.FailOnError(err, "Couldn't start dynamic DNS server resolver")
	defer servers.Stop()

	var resolver bdns.Client
	if !c.VA.DNSAllowLoopbackAddresses {
		resolver = bdns.New(
			c.VA.DNSTimeout.Duration,
			servers,
			scope,
			clk,
			dnsTries,
			logger)
	} else {
		resolver = bdns.NewTest(
			c.VA.DNSTimeout.Duration,
			servers,
			scope,
			clk,
			dnsTries,
			logger)
	}

	tlsConfig, err := c.VA.TLS.Load(scope)
	cmd.FailOnError(err, "tlsConfig config")

	var remotes []va.RemoteVA
	if len(c.VA.RemoteVAs) > 0 {
		for _, rva := range c.VA.RemoteVAs {
			rva := rva
			vaConn, err := bgrpc.ClientSetup(&rva, tlsConfig, scope, clk)
			cmd.FailOnError(err, "Unable to create remote VA client")
			remotes = append(
				remotes,
				va.RemoteVA{
					VAClient: vapb.NewVAClient(vaConn),
					Address:  rva.ServerAddress,
				},
			)
		}
	}

	vai, err := va.NewValidationAuthorityImpl(
		resolver,
		remotes,
		c.VA.MaxRemoteValidationFailures,
		c.VA.UserAgent,
		c.VA.IssuerDomain,
		scope,
		clk,
		logger,
		c.VA.AccountURIPrefixes)
	cmd.FailOnError(err, "Unable to create VA server")

	start, err := bgrpc.NewServer(c.VA.GRPC, logger).Add(
		&vapb.VA_ServiceDesc, vai).Add(
		&vapb.CAA_ServiceDesc, vai).Build(tlsConfig, scope, clk)
	cmd.FailOnError(err, "Unable to setup VA gRPC server")

	cmd.FailOnError(start(), "VA gRPC service failed")
}

func init() {
	cmd.RegisterCommand("boulder-va", main, &cmd.ConfigValidator{Config: &Config{}})
	// We register under two different names, because it's convenient for the
	// remote VAs to show up under a different program name when looking at logs.
	cmd.RegisterCommand("boulder-remoteva", main, &cmd.ConfigValidator{Config: &Config{}})
}
