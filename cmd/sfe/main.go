package notmain

import (
	"context"
	"flag"
	"net/http"
	"os"
	"sync"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/ratelimits"
	bredis "github.com/letsencrypt/boulder/redis"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/sfe"
	"github.com/letsencrypt/boulder/sfe/zendesk"
	"github.com/letsencrypt/boulder/web"
)

type Config struct {
	SFE struct {
		DebugAddr string `validate:"omitempty,hostname_port"`

		// ListenAddress is the address:port on which to listen for incoming
		// HTTP requests. Defaults to ":80".
		ListenAddress string `validate:"omitempty,hostname_port"`

		// Timeout is the per-request overall timeout. This should be slightly
		// lower than the upstream's timeout when making requests to this service.
		Timeout config.Duration `validate:"-"`

		// ShutdownStopTimeout determines the maximum amount of time to wait
		// for extant request handlers to complete before exiting. It should be
		// greater than Timeout.
		ShutdownStopTimeout config.Duration

		TLS cmd.TLSConfig

		RAService *cmd.GRPCClientConfig
		SAService *cmd.GRPCClientConfig

		// UnpauseHMACKey validates incoming JWT signatures at the unpause
		// endpoint. This key must be the same as the one configured for all
		// WFEs. This field is required to enable the pausing feature.
		UnpauseHMACKey cmd.HMACKeyConfig

		Zendesk *struct {
			BaseURL      string             `validate:"required,url"`
			TokenEmail   string             `validate:"required,email"`
			Token        cmd.PasswordConfig `validate:"required,dive"`
			CustomFields struct {
				Organization     int64 `validate:"required"`
				Tier             int64 `validate:"required"`
				RateLimit        int64 `validate:"required"`
				ReviewStatus     int64 `validate:"required"`
				AccountURI       int64 `validate:"required"`
				RegisteredDomain int64 `validate:"required"`
				IPAddress        int64 `validate:"required"`
			} `validate:"required,dive"`
		} `validate:"omitempty,dive"`

		Limiter struct {
			// Redis contains the configuration necessary to connect to Redis
			// for rate limiting. This field is required to enable rate
			// limiting.
			Redis *bredis.Config `validate:"required_with=Defaults"`

			// Defaults is a path to a YAML file containing default rate limits.
			// See: ratelimits/README.md for details. This field is required to
			// enable rate limiting. If any individual rate limit is not set,
			// that limit will be disabled. Failed Authorizations limits passed
			// in this file must be identical to those in the RA.
			Defaults string `validate:"required_with=Redis"`
		}

		// OverridesImporter configures the periodic import of approved rate
		// limit override requests from Zendesk.
		OverridesImporter struct {
			// Mode controls which tickets are processed. Valid values are:
			//   - "all": process all tickets
			//   - "even": process only tickets with even IDs
			//   - "odd": process only tickets with odd IDs
			// If unspecified or empty, defaults to "all".
			Mode string `validate:"omitempty,required_with=Interval,oneof=all even odd"`
			// Interval is the amount of time between runs of the importer. If
			// zero or unspecified, the importer is disabled. Minimum value is
			// 20 minutes.
			Interval config.Duration `validate:"omitempty,required_with=Mode,min=1200s"`
		} `validate:"omitempty,dive"`
		Features features.Config
	}

	Syslog        cmd.SyslogConfig
	OpenTelemetry cmd.OpenTelemetryConfig

	// OpenTelemetryHTTPConfig configures tracing on incoming HTTP requests
	OpenTelemetryHTTPConfig cmd.OpenTelemetryHTTPConfig
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

	clk := clock.New()

	unpauseHMACKey, err := c.SFE.UnpauseHMACKey.Load()
	cmd.FailOnError(err, "Failed to load unpauseHMACKey")

	tlsConfig, err := c.SFE.TLS.Load(stats)
	cmd.FailOnError(err, "TLS config")

	raConn, err := bgrpc.ClientSetup(c.SFE.RAService, tlsConfig, stats, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to RA")
	rac := rapb.NewRegistrationAuthorityClient(raConn)

	saConn, err := bgrpc.ClientSetup(c.SFE.SAService, tlsConfig, stats, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := sapb.NewStorageAuthorityReadOnlyClient(saConn)

	var zendeskClient *zendesk.Client
	var overridesImporterShutdown func()
	var overridesImporterWG sync.WaitGroup
	if c.SFE.Zendesk != nil {
		zendeskToken, err := c.SFE.Zendesk.Token.Pass()
		cmd.FailOnError(err, "Failed to load Zendesk token")

		zendeskClient, err = zendesk.NewClient(
			c.SFE.Zendesk.BaseURL,
			c.SFE.Zendesk.TokenEmail,
			zendeskToken,
			map[string]int64{
				sfe.OrganizationFieldName:     c.SFE.Zendesk.CustomFields.Organization,
				sfe.TierFieldName:             c.SFE.Zendesk.CustomFields.Tier,
				sfe.RateLimitFieldName:        c.SFE.Zendesk.CustomFields.RateLimit,
				sfe.ReviewStatusFieldName:     c.SFE.Zendesk.CustomFields.ReviewStatus,
				sfe.AccountURIFieldName:       c.SFE.Zendesk.CustomFields.AccountURI,
				sfe.RegisteredDomainFieldName: c.SFE.Zendesk.CustomFields.RegisteredDomain,
				sfe.IPAddressFieldName:        c.SFE.Zendesk.CustomFields.IPAddress,
			},
		)
		if err != nil {
			cmd.FailOnError(err, "Failed to create Zendesk client")
		}

		if c.SFE.OverridesImporter.Interval.Duration > 0 {
			mode := sfe.ProcessMode(c.SFE.OverridesImporter.Mode)
			if mode == "" {
				mode = sfe.ProcessAll
			}

			importer, ierr := sfe.NewOverridesImporter(
				mode,
				c.SFE.OverridesImporter.Interval.Duration,
				zendeskClient,
				rac,
				clk,
				logger,
			)
			cmd.FailOnError(ierr, "Creating overrides importer")

			var ctx context.Context
			ctx, overridesImporterShutdown = context.WithCancel(context.Background())
			overridesImporterWG.Go(func() {
				importer.Start(ctx)
			})
			logger.Infof("Overrides importer started with mode=%s interval=%s", mode, c.SFE.OverridesImporter.Interval.Duration)
		}
	}

	var limiter *ratelimits.Limiter
	var txnBuilder *ratelimits.TransactionBuilder
	var limiterRedis *bredis.Ring
	if c.SFE.Limiter.Defaults != "" {
		limiterRedis, err = bredis.NewRingFromConfig(*c.SFE.Limiter.Redis, stats, logger)
		cmd.FailOnError(err, "Failed to create Redis ring")

		source := ratelimits.NewRedisSource(limiterRedis.Ring, clk, stats)
		limiter, err = ratelimits.NewLimiter(clk, source, stats)
		cmd.FailOnError(err, "Failed to create rate limiter")
		txnBuilder, err = ratelimits.NewTransactionBuilderFromFiles(c.SFE.Limiter.Defaults, "")
		cmd.FailOnError(err, "Failed to create rate limits transaction builder")
	}

	sfei, err := sfe.NewSelfServiceFrontEndImpl(
		stats,
		clk,
		logger,
		c.SFE.Timeout.Duration,
		rac,
		sac,
		unpauseHMACKey,
		zendeskClient,
		limiter,
		txnBuilder,
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
		if overridesImporterShutdown != nil {
			overridesImporterShutdown()
			overridesImporterWG.Wait()
		}
		_ = srv.Shutdown(ctx)
		oTelShutdown(ctx)
	}()

	cmd.WaitForSignal()
}

func init() {
	cmd.RegisterCommand("sfe", main, &cmd.ConfigValidator{Config: &Config{}})
}
