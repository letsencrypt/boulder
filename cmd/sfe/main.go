package notmain

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/sfe"
)

type Config struct {
	SFE struct {
		DebugAddr string `validate:"omitempty,hostname_port"`

		// ListenAddress is the address:port on which to listen for incoming
		// HTTP requests. Defaults to ":80".
		ListenAddress string `validate:"omitempty,hostname_port"`

		// TLSListenAddress is the address:port on which to listen for incoming
		// HTTPS requests. If none is provided the SFE will not listen for HTTPS
		// requests.
		TLSListenAddress string `validate:"omitempty,hostname_port"`

		// Timeout is the per-request overall timeout. This should be slightly
		// lower than the upstream's timeout when making request to the SFE.
		Timeout config.Duration `validate:"-"`

		// ShutdownStopTimeout is the duration that the SFE will wait before
		// shutting down any listening servers.
		ShutdownStopTimeout config.Duration

		ServerCertificatePath string `validate:"required_with=TLSListenAddress"`
		ServerKeyPath         string `validate:"required_with=TLSListenAddress"`

		TLS cmd.TLSConfig

		RAService *cmd.GRPCClientConfig
		SAService *cmd.GRPCClientConfig

		Unpause struct {
			// Seed is a secret that should contain 256 bits (32 bytes) of
			// random data used to derive an x/crypto/ed25519 keypair (e.g. the
			// output of `openssl rand -hex 16`). In a multi-DC deployment this
			// value should be the same across all boulder-wfe and sfe
			// instances.
			Seed cmd.PasswordConfig `validate:"-"`
		}

		Features features.Config
	}

	Syslog        cmd.SyslogConfig
	OpenTelemetry cmd.OpenTelemetryConfig

	// OpenTelemetryHTTPConfig configures tracing on incoming HTTP requests
	OpenTelemetryHTTPConfig cmd.OpenTelemetryHTTPConfig
}

func setupSFE(c Config, scope prometheus.Registerer, clk clock.Clock) (rapb.RegistrationAuthorityClient, sapb.StorageAuthorityReadOnlyClient, string) {
	var unpauseSeed string
	if c.SFE.Unpause.Seed.PasswordFile != "" {
		var err error
		unpauseSeed, err = c.SFE.Unpause.Seed.Pass()
		cmd.FailOnError(err, "Failed to load unpauseKey")
		if unpauseSeed == "" {
			cmd.Fail("unpauseKey must not be empty")
		}
		// The seed is used to generate an x/crypto/ed25519 keypair which
		// requires a SeedSize of 32 bytes or the generator will panic.
		if len(unpauseSeed) != 32 {
			cmd.Fail("unpauseSeed should be 32 hexadecimal characters e.g. the output of 'openssl rand -hex 16'")
		}
	}

	tlsConfig, err := c.SFE.TLS.Load(scope)
	cmd.FailOnError(err, "TLS config")

	raConn, err := bgrpc.ClientSetup(c.SFE.RAService, tlsConfig, scope, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to RA")
	rac := rapb.NewRegistrationAuthorityClient(raConn)

	saConn, err := bgrpc.ClientSetup(c.SFE.SAService, tlsConfig, scope, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := sapb.NewStorageAuthorityReadOnlyClient(saConn)

	return rac, sac, unpauseSeed
}

type errorWriter struct {
	blog.Logger
}

func (ew errorWriter) Write(p []byte) (n int, err error) {
	// log.Logger will append a newline to all messages before calling
	// Write. Our log checksum checker doesn't like newlines, because
	// syslog will strip them out so the calculated checksums will
	// differ. So that we don't hit this corner case for every line
	// logged from inside net/http.Server we strip the newline before
	// we get to the checksum generator.
	p = bytes.TrimRight(p, "\n")
	ew.Logger.Err(fmt.Sprintf("net/http.Server: %s", string(p)))
	return
}

func main() {
	listenAddr := flag.String("addr", "", "HTTP listen address override")
	tlsAddr := flag.String("tls-addr", "", "HTTPS listen address override")
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
	if *tlsAddr != "" {
		c.SFE.TLSListenAddress = *tlsAddr
	}
	if *debugAddr != "" {
		c.SFE.DebugAddr = *debugAddr
	}

	stats, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, c.SFE.DebugAddr)
	logger.Info(cmd.VersionString())

	clk := cmd.Clock()

	rac, sac, unpauseSeed := setupSFE(c, stats, clk)

	sfei, err := sfe.NewSelfServiceFrontEndImpl(
		stats,
		clk,
		logger,
		c.SFE.Timeout.Duration,
		rac,
		sac,
		unpauseSeed,
	)
	cmd.FailOnError(err, "Unable to create SFE")

	logger.Infof("Server running, listening on %s....", c.SFE.ListenAddress)
	handler := sfei.Handler(stats, c.OpenTelemetryHTTPConfig.Options()...)

	srv := http.Server{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
		Addr:         c.SFE.ListenAddress,
		ErrorLog:     log.New(errorWriter{logger}, "", 0),
		Handler:      handler,
	}

	go func() {
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			cmd.FailOnError(err, "Running HTTP server")
		}
	}()

	tlsSrv := http.Server{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
		Addr:         c.SFE.TLSListenAddress,
		ErrorLog:     log.New(errorWriter{logger}, "", 0),
		Handler:      handler,
	}
	if tlsSrv.Addr != "" {
		go func() {
			logger.Infof("TLS server listening on %s", tlsSrv.Addr)
			err := tlsSrv.ListenAndServeTLS(c.SFE.ServerCertificatePath, c.SFE.ServerKeyPath)
			if err != nil && err != http.ErrServerClosed {
				cmd.FailOnError(err, "Running TLS server")
			}
		}()
	}

	// When main is ready to exit (because it has received a shutdown signal),
	// gracefully shutdown the servers. Calling these shutdown functions causes
	// ListenAndServe() and ListenAndServeTLS() to immediately return, then waits
	// for any lingering connection-handling goroutines to finish their work.
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), c.SFE.ShutdownStopTimeout.Duration)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = tlsSrv.Shutdown(ctx)
		oTelShutdown(ctx)
	}()

	cmd.WaitForSignal()
}

func init() {
	cmd.RegisterCommand("sfe", main, &cmd.ConfigValidator{Config: &Config{}})
}
