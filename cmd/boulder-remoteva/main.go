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
	RVA struct {
		cmd.ServiceConfig

		UserAgent string

		IssuerDomain string

		// DNSTries is the number of times to try a DNS query (that has a temporary error)
		// before giving up. May be short-circuited by deadlines. A zero value
		// will be turned into 1.
		DNSTries    int
		DNSProvider *cmd.DNSProvider `validate:"required_without=DNSStaticResolvers"`
		// DNSStaticResolvers is a list of DNS resolvers. Each entry must
		// be a host or IP and port separated by a colon. IPv6 addresses
		// must be enclosed in square brackets.
		DNSStaticResolvers        []string        `validate:"required_without=DNSProvider,dive,hostname_port"`
		DNSTimeout                config.Duration `validate:"required"`
		DNSAllowLoopbackAddresses bool

		MaxRemoteValidationFailures int `validate:"omitempty,min=0,required_with=RemoteVAs"`

		Features features.Config

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
		nil, // A remote VA itself must not have downstream remotes.
		c.RVA.MaxRemoteValidationFailures,
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
	cmd.RegisterCommand("boulder-remoteva", main, &cmd.ConfigValidator{Config: &Config{}})
}
