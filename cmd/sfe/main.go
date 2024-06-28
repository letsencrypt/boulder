package notmain

import (
	"context"
	"crypto/ed25519"
	"flag"
	"net/http"
	"os"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/sfe"
	"github.com/letsencrypt/boulder/web"
)

type Config struct {
	SFE struct {
		DebugAddr string `validate:"omitempty,hostname_port"`

		// ListenAddress is the address:port on which to listen for incoming
		// HTTP requests. Defaults to ":80".
		ListenAddress string `validate:"omitempty,hostname_port"`

		// Timeout is the per-request overall timeout. This should be slightly
		// lower than the upstream's timeout when making requests to the SFE.
		Timeout config.Duration `validate:"-"`

		// ShutdownStopTimeout is the duration that the SFE will wait before
		// shutting down any listening servers.
		ShutdownStopTimeout config.Duration

		TLS cmd.TLSConfig

		RAService *cmd.GRPCClientConfig
		SAService *cmd.GRPCClientConfig

		Features features.Config
	}

	Unpause cmd.UnpauseConfig

	Syslog        cmd.SyslogConfig
	OpenTelemetry cmd.OpenTelemetryConfig

	// OpenTelemetryHTTPConfig configures tracing on incoming HTTP requests
	OpenTelemetryHTTPConfig cmd.OpenTelemetryHTTPConfig
}

func setupSFE(c Config, scope prometheus.Registerer, clk clock.Clock) (rapb.RegistrationAuthorityClient, sapb.StorageAuthorityReadOnlyClient, ed25519.PrivateKey) {
	privateKey, err := c.Unpause.GenerateKeyPair()
	cmd.FailOnError(err, "Unpause key generation")

	tlsConfig, err := c.SFE.TLS.Load(scope)
	cmd.FailOnError(err, "TLS config")

	raConn, err := bgrpc.ClientSetup(c.SFE.RAService, tlsConfig, scope, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to RA")
	rac := rapb.NewRegistrationAuthorityClient(raConn)

	saConn, err := bgrpc.ClientSetup(c.SFE.SAService, tlsConfig, scope, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := sapb.NewStorageAuthorityReadOnlyClient(saConn)

	return rac, sac, privateKey
}

func main() {
	listenAddr := flag.String("addr", "", "HTTP listen address override")
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

	features.Set(c.SFE.Features)

	if *listenAddr != "" {
		c.SFE.ListenAddress = *listenAddr
	}
	if c.SFE.ListenAddress == "" {
		cmd.Fail("HTTP listen address is not configured")
	}
	if *debugAddr != "" {
		c.SFE.DebugAddr = *debugAddr
	}

	stats, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, c.SFE.DebugAddr)
	logger.Info(cmd.VersionString())

	clk := cmd.Clock()

	rac, sac, unpausePrivateKey := setupSFE(c, stats, clk)

	sfei, err := sfe.NewSelfServiceFrontEndImpl(
		stats,
		clk,
		logger,
		c.SFE.Timeout.Duration,
		rac,
		sac,
		unpausePrivateKey.Public().(ed25519.PublicKey),
	)
	cmd.FailOnError(err, "Unable to create SFE")

	logger.Infof("Server running, listening on %s....", c.SFE.ListenAddress)
	handler := sfei.Handler(stats, c.OpenTelemetryHTTPConfig.Options()...)

	srv := web.NewServer(c.SFE.ListenAddress, handler, logger)
	go func() {
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			cmd.FailOnError(err, "Running HTTP server")
		}
	}()

	// When main is ready to exit (because it has received a shutdown signal),
	// gracefully shutdown the servers. Calling these shutdown functions causes
	// ListenAndServe() and ListenAndServeTLS() to immediately return, then waits
	// for any lingering connection-handling goroutines to finish their work.
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), c.SFE.ShutdownStopTimeout.Duration)
		defer cancel()
		_ = srv.Shutdown(ctx)
		oTelShutdown(ctx)
	}()

	cmd.WaitForSignal()
}

func init() {
	cmd.RegisterCommand("sfe", main, &cmd.ConfigValidator{Config: &Config{}})
}
