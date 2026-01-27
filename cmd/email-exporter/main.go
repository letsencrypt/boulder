package notmain

import (
	"context"
	"flag"
	"os"

	"github.com/jmhodges/clock"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/letsencrypt/boulder/cmd"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/salesforce"
	emailpb "github.com/letsencrypt/boulder/salesforce/email/proto"
	salesforcepb "github.com/letsencrypt/boulder/salesforce/proto"
)

// Config holds the configuration for the email-exporter service.
type Config struct {
	EmailExporter struct {
		cmd.ServiceConfig

		// PerDayLimit enforces the daily request limit imposed by the Pardot
		// API. The total daily limit, which varies based on the Salesforce
		// Pardot subscription tier, must be distributed among all
		// email-exporter instances. For more information, see:
		// https://developer.salesforce.com/docs/marketing/pardot/guide/overview.html?q=rate+limits#daily-requests-limits
		PerDayLimit float64 `validate:"required,min=1"`

		// MaxConcurrentRequests enforces the concurrent request limit imposed
		// by the Pardot API. This limit must be distributed among all
		// email-exporter instances and be proportional to each instance's
		// PerDayLimit. For example, if the total daily limit is 50,000 and one
		// instance is assigned 40% (20,000 requests), it should also receive
		// 40% of the max concurrent requests (2 out of 5). For more
		// information, see:
		// https://developer.salesforce.com/docs/marketing/pardot/guide/overview.html?q=rate+limits#concurrent-requests
		MaxConcurrentRequests int `validate:"required,min=1,max=5"`

		// PardotBusinessUnit is the Pardot business unit to use.
		PardotBusinessUnit string `validate:"required"`

		// ClientId is the OAuth API client ID provided by Salesforce.
		ClientId cmd.PasswordConfig

		// ClientSecret is the OAuth API client secret provided by Salesforce.
		ClientSecret cmd.PasswordConfig

		// SalesforceBaseURL is the base URL for the Salesforce API. (e.g.,
		// "https://company.salesforce.com")
		SalesforceBaseURL string `validate:"required"`

		// PardotBaseURL is the base URL for the Pardot API. (e.g.,
		// "https://pi.pardot.com")
		PardotBaseURL string `validate:"required"`

		// EmailCacheSize controls how many hashed email addresses are retained
		// in memory to prevent duplicates from being sent to the Pardot API.
		// Each entry consumes ~120 bytes, so 100,000 entries uses around 12 MB
		// of memory. If left unset, no caching is performed.
		EmailCacheSize int `validate:"omitempty,min=1"`
	}
	Syslog        cmd.SyslogConfig
	OpenTelemetry cmd.OpenTelemetryConfig
}

// legacyEmailExporterServer is an adapter that implements the email.Exporter
// gRPC interface by delegating to an inner salesforce.Exporter server.
//
// TODO(#8410): Remove legacyEmailExporterServer once fully migrated to
// salesforcepb.Exporter.
type legacyEmailExporterServer struct {
	emailpb.UnimplementedExporterServer
	inner salesforcepb.ExporterServer
}

// SendContacts is an interface adapter that forwards the request to the same
// method on the inner salesforce.Exporter server.
func (s legacyEmailExporterServer) SendContacts(ctx context.Context, req *emailpb.SendContactsRequest) (*emptypb.Empty, error) {
	return s.inner.SendContacts(ctx, &salesforcepb.SendContactsRequest{Emails: req.GetEmails()})
}

// SendCase is an interface adapter that forwards the request to the same method
// on the inner salesforce.Exporter server.
func (s legacyEmailExporterServer) SendCase(ctx context.Context, req *emailpb.SendCaseRequest) (*emptypb.Empty, error) {
	return s.inner.SendCase(ctx, &salesforcepb.SendCaseRequest{
		Origin:        req.GetOrigin(),
		Subject:       req.GetSubject(),
		Description:   req.GetDescription(),
		ContactEmail:  req.GetContactEmail(),
		Organization:  req.GetOrganization(),
		AccountId:     req.GetAccountId(),
		RateLimitName: req.GetRateLimitName(),
		RateLimitTier: req.GetRateLimitTier(),
		UseCase:       req.GetUseCase(),
	})
}

func main() {
	configFile := flag.String("config", "", "Path to configuration file")
	grpcAddr := flag.String("addr", "", "gRPC listen address override")
	debugAddr := flag.String("debug-addr", "", "Debug server address override")
	flag.Parse()

	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c Config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	if *grpcAddr != "" {
		c.EmailExporter.ServiceConfig.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.EmailExporter.ServiceConfig.DebugAddr = *debugAddr
	}

	scope, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, c.EmailExporter.ServiceConfig.DebugAddr)
	defer oTelShutdown(context.Background())

	cmd.LogStartup(logger)

	clk := clock.New()
	clientId, err := c.EmailExporter.ClientId.Pass()
	cmd.FailOnError(err, "Loading clientId")
	clientSecret, err := c.EmailExporter.ClientSecret.Pass()
	cmd.FailOnError(err, "Loading clientSecret")

	var cache *salesforce.EmailCache
	if c.EmailExporter.EmailCacheSize > 0 {
		cache = salesforce.NewHashedEmailCache(c.EmailExporter.EmailCacheSize, scope)
	}

	sfClient, err := salesforce.NewSalesforceClientImpl(
		clk,
		c.EmailExporter.PardotBusinessUnit,
		clientId,
		clientSecret,
		c.EmailExporter.SalesforceBaseURL,
		c.EmailExporter.PardotBaseURL,
	)
	cmd.FailOnError(err, "Creating Pardot API client")
	server := salesforce.NewExporterImpl(sfClient, cache, c.EmailExporter.PerDayLimit, c.EmailExporter.MaxConcurrentRequests, scope, logger)

	tlsConfig, err := c.EmailExporter.TLS.Load(scope)
	cmd.FailOnError(err, "Loading email-exporter TLS config")

	daemonCtx, shutdown := context.WithCancel(context.Background())
	go server.Start(daemonCtx)

	start, err := bgrpc.NewServer(c.EmailExporter.GRPC, logger).Add(
		&salesforcepb.Exporter_ServiceDesc, server).Add(
		// TODO(#8410): Remove emailpb.Exporter once fully migrated to
		// salesforcepb.Exporter.
		&emailpb.Exporter_ServiceDesc, legacyEmailExporterServer{inner: server}).Build(
		tlsConfig, scope, clk)
	cmd.FailOnError(err, "Configuring email-exporter gRPC server")

	err = start()
	shutdown()
	server.Drain()
	cmd.FailOnError(err, "email-exporter gRPC service failed to start")
}

func init() {
	cmd.RegisterCommand("email-exporter", main, &cmd.ConfigValidator{Config: &Config{}})
}
