package notmain

import (
	"context"
	"flag"
	"os"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/iana"
	"github.com/letsencrypt/boulder/va"
	vaConfig "github.com/letsencrypt/boulder/va/config"
	vapb "github.com/letsencrypt/boulder/va/proto"
)

// RemoteVAGRPCClientConfig  contains the information necessary to setup a gRPC
// client connection. The following GRPC client configuration field combinations
// are allowed:
//
// ServerAddress, DNSAuthority, [Timeout], [HostOverride]
// SRVLookup, DNSAuthority, [Timeout], [HostOverride], [SRVResolver]
// SRVLookups, DNSAuthority, [Timeout], [HostOverride], [SRVResolver]
type RemoteVAGRPCClientConfig struct {
	cmd.GRPCClientConfig
	// Perspective uniquely identifies the Network Perspective used to
	// perform the validation, as specified in BRs Section 5.4.1,
	// Requirement 2.7 ("Multi-Perspective Issuance Corroboration attempts
	// from each Network Perspective"). It should uniquely identify a group
	// of RVAs deployed in the same datacenter.
	Perspective string `validate:"required"`

	// RIR indicates the Regional Internet Registry where this RVA is
	// located. This field is used to identify the RIR region from which a
	// given validation was performed, as specified in the "Phased
	// Implementation Timeline" in BRs Section 3.2.2.9. It must be one of
	// the following values:
	//   - ARIN
	//   - RIPE
	//   - APNIC
	//   - LACNIC
	//   - AFRINIC
	RIR string `validate:"required,oneof=ARIN RIPE APNIC LACNIC AFRINIC"`
}

type Config struct {
	VA struct {
		vaConfig.Common
		RemoteVAs []RemoteVAGRPCClientConfig `validate:"omitempty,dive"`
		// SlowRemoteTimeout sets how long the VA is willing to wait for slow
		// RemoteVA instances to finish their work. It starts counting from
		// when the VA first gets a quorum of (un)successful remote results.
		// Leaving this value zero means the VA won't early-cancel slow remotes.
		SlowRemoteTimeout config.Duration

		// ExperimentalVA configures an optional parallel VA that repeats the
		// primary VA's DCV and CAA checks using an alternative DNS resolver,
		// emitting comparison metrics without affecting the real validation
		// decision.
		ExperimentalVA *struct {
			// DNSProvider is the dynamic DNS provider config for the
			// experimental VA's resolver.
			DNSProvider *cmd.DNSProvider `validate:"required"`
			// DNSTimeout is the timeout for DNS queries. Defaults to the
			// primary VA's DNSTimeout if unset.
			DNSTimeout config.Duration `validate:"omitempty"`
			// SampleRate controls the rate of validations that are repeated
			// (0.0 to 1.0). A value of 0 disables it entirely, while 1 repeats
			// all validations.
			SampleRate float64 `validate:"min=0,max=1"`
			// Timeout is the timeout for experimental validation operations.
			// This should be configured to match the RA->VA timeout.
			Timeout config.Duration `validate:"required"`
		}
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
	err = c.VA.SetDefaultsAndValidate(grpcAddr, debugAddr)
	cmd.FailOnError(err, "Setting and validating default config values")

	features.Set(c.VA.Features)
	scope, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, c.VA.DebugAddr)
	defer oTelShutdown(context.Background())
	cmd.LogStartup(logger)
	clk := clock.New()

	var servers bdns.ServerProvider

	if len(c.VA.DNSStaticResolvers) != 0 {
		servers, err = bdns.NewStaticProvider(c.VA.DNSStaticResolvers)
		cmd.FailOnError(err, "Couldn't start static DNS server resolver")
	} else {
		servers, err = bdns.StartDynamicProvider(c.VA.DNSProvider, 60*time.Second, "tcp")
		cmd.FailOnError(err, "Couldn't start dynamic DNS server resolver")
	}
	defer servers.Stop()

	tlsConfig, err := c.VA.TLS.Load(scope)
	cmd.FailOnError(err, "tlsConfig config")

	resolver := bdns.New(
		c.VA.DNSTimeout.Duration,
		servers,
		scope,
		clk,
		c.VA.DNSTries,
		c.VA.UserAgent,
		logger,
		tlsConfig)

	var remotes []va.RemoteVA
	if len(c.VA.RemoteVAs) > 0 {
		for _, rva := range c.VA.RemoteVAs {
			vaConn, err := bgrpc.ClientSetup(&rva.GRPCClientConfig, tlsConfig, scope, clk)
			cmd.FailOnError(err, "Unable to create remote VA client")
			remotes = append(
				remotes,
				va.RemoteVA{
					RemoteClients: va.RemoteClients{
						VAClient:  vapb.NewVAClient(vaConn),
						CAAClient: vapb.NewCAAClient(vaConn),
					},
					Address:     rva.ServerAddress,
					Perspective: rva.Perspective,
					RIR:         rva.RIR,
				},
			)
		}
	}

	var experimentalVA *va.ValidationAuthorityImpl
	var experimentalVASampleRate float64
	var experimentalVATimeout time.Duration
	if c.VA.ExperimentalVA != nil {
		servers, err := bdns.StartDynamicProvider(c.VA.ExperimentalVA.DNSProvider, 60*time.Second, "tcp")
		cmd.FailOnError(err, "Couldn't start experimental dynamic DNS server resolver")
		defer servers.Stop()

		dnsTimeout := c.VA.ExperimentalVA.DNSTimeout.Duration
		if dnsTimeout <= 0 {
			dnsTimeout = c.VA.DNSTimeout.Duration
		}

		// Prefix experimental VA metrics to avoid metric name collisions with
		// the primary VA.
		scope := prometheus.WrapRegistererWithPrefix("experimental_", scope)

		resolver := bdns.New(
			dnsTimeout,
			servers,
			scope,
			clk,
			c.VA.DNSTries,
			c.VA.UserAgent,
			logger,
			tlsConfig,
		)

		experimentalVA, err = va.NewValidationAuthorityImpl(
			resolver,
			nil,
			c.VA.UserAgent,
			c.VA.IssuerDomain,
			scope,
			clk,
			logger,
			c.VA.AccountURIPrefixes,
			"Experimental",
			"",
			iana.IsReservedAddr,
			0,
			c.VA.DNSAllowLoopbackAddresses,
			nil,
			0,
			0,
		)
		cmd.FailOnError(err, "Unable to create experimental VA")
		experimentalVASampleRate = c.VA.ExperimentalVA.SampleRate
		experimentalVATimeout = c.VA.ExperimentalVA.Timeout.Duration
	}

	vai, err := va.NewValidationAuthorityImpl(
		resolver,
		remotes,
		c.VA.UserAgent,
		c.VA.IssuerDomain,
		scope,
		clk,
		logger,
		c.VA.AccountURIPrefixes,
		va.PrimaryPerspective,
		"",
		iana.IsReservedAddr,
		c.VA.SlowRemoteTimeout.Duration,
		c.VA.DNSAllowLoopbackAddresses,
		experimentalVA,
		experimentalVASampleRate,
		experimentalVATimeout,
	)
	cmd.FailOnError(err, "Unable to create VA server")

	start, err := bgrpc.NewServer(c.VA.GRPC, logger).Add(
		&vapb.VA_ServiceDesc, vai).Add(
		&vapb.CAA_ServiceDesc, vai).Build(tlsConfig, scope, clk)
	cmd.FailOnError(err, "Unable to setup VA gRPC server")
	cmd.FailOnError(start(), "VA gRPC service failed")
}

func init() {
	cmd.RegisterCommand("boulder-va", main, &cmd.ConfigValidator{Config: &Config{}})
}
