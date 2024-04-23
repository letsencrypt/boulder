package notmain

import (
	"context"
	"flag"
	"os"

	"github.com/letsencrypt/boulder/cmd"
	vaCommon "github.com/letsencrypt/boulder/cmd/boulder-va"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/va"
	vacfg "github.com/letsencrypt/boulder/va/config"
	vapb "github.com/letsencrypt/boulder/va/proto"
)

type Config struct {
	VA struct {
		vacfg.Common
		RemoteVAs                   []cmd.GRPCClientConfig `validate:"omitempty,dive"`
		MaxRemoteValidationFailures int                    `validate:"omitempty,min=0,required_with=RemoteVAs"`
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

	features.Set(c.VA.Features)

	if *grpcAddr != "" {
		c.VA.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.VA.DebugAddr = *debugAddr
	}

	scope, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, c.VA.DebugAddr)
	defer oTelShutdown(context.Background())
	logger.Info(cmd.VersionString())

	servers, err := vaCommon.SetupServerResolvers(c.VA.DNSStaticResolvers, c.VA.DNSProvider)
	if err != nil {
		cmd.Fail(err.Error())
	}
	defer servers.Stop()

	tlsConfig, err := c.VA.TLS.Load(scope)
	cmd.FailOnError(err, "tlsConfig config")

	if c.VA.DNSTimeout.Duration == 0 {
		cmd.Fail("'dnsTimeout' is required")
	}
	clk := cmd.Clock()
	resolver := vaCommon.SetupClientResolver(c.VA.DNSTimeout.Duration, servers, scope, clk, c.VA.DNSTries, logger, tlsConfig, c.VA.DNSAllowLoopbackAddresses)

	var remotes []va.RemoteVA
	if len(c.VA.RemoteVAs) > 0 {
		for _, rva := range c.VA.RemoteVAs {
			rva := rva
			vaConn, err := bgrpc.ClientSetup(&rva, tlsConfig, scope, clk)
			cmd.FailOnError(err, "Unable to create remote VA client")
			remotes = append(
				remotes,
				va.RemoteVA{
					RemoteClients: va.RemoteClients{
						VAClient:  vapb.NewVAClient(vaConn),
						CAAClient: vapb.NewCAAClient(vaConn),
					},
					Address: rva.ServerAddress,
				},
			)
		}
	}

	start, err := vaCommon.SetupNewVAImplAndStartServer(resolver, remotes, c.VA.MaxRemoteValidationFailures, c.VA.UserAgent, c.VA.IssuerDomain, scope, clk, logger, c.VA.AccountURIPrefixes, c.VA.GRPC, tlsConfig)
	if err != nil {
		cmd.Fail(err.Error())
	}
	cmd.FailOnError(start(), "VA gRPC service failed")
}

func init() {
	cmd.RegisterCommand("boulder-va", main, &cmd.ConfigValidator{Config: &Config{}})
}
