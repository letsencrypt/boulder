package main

import (
	"context"
	"flag"
	"os"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/akamai"
	akamaipb "github.com/letsencrypt/boulder/akamai/proto"
	"github.com/letsencrypt/boulder/cmd"
	corepb "github.com/letsencrypt/boulder/core/proto"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
)

type config struct {
	AkamaiPurger struct {
		cmd.ServiceConfig

		PurgeInterval cmd.ConfigDuration

		BaseURL           string
		ClientToken       string
		ClientSecret      string
		AccessToken       string
		V3Network         string
		PurgeRetries      int
		PurgeRetryBackoff cmd.ConfigDuration
	}
	Syslog cmd.SyslogConfig
}

type akamaiPurger struct {
	mu      sync.Mutex
	toPurge []string

	client *akamai.CachePurgeClient
	log    blog.Logger
}

func (ap *akamaiPurger) purge() {
	ap.mu.Lock()
	urls := ap.toPurge[:]
	ap.toPurge = []string{}
	ap.mu.Unlock()
	if len(urls) == 0 {
		return
	}

	if err := ap.client.Purge(urls); err != nil {
		// Add the URLs back to the queue?
		ap.mu.Lock()
		ap.toPurge = append(urls, ap.toPurge...)
		ap.mu.Unlock()
		ap.log.Errf("Failed to purge URLs: %s", err)
	}
}

func (ap *akamaiPurger) Purge(ctx context.Context, req *akamaipb.PurgeRequest) (*corepb.Empty, error) {
	ap.mu.Lock()
	defer ap.mu.Unlock()
	ap.toPurge = append(ap.toPurge, req.Urls...)
	return &corepb.Empty{}, nil
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

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	if *grpcAddr != "" {
		c.AkamaiPurger.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.AkamaiPurger.DebugAddr = *debugAddr
	}

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.AkamaiPurger.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	clk := cmd.Clock()

	tlsConfig, err := c.AkamaiPurger.TLS.Load()
	cmd.FailOnError(err, "tlsConfig config")

	if c.AkamaiPurger.PurgeInterval.Duration == 0 {
		cmd.Fail("PurgeInterval must be > 0")
	}

	ccu, err := akamai.NewCachePurgeClient(
		c.AkamaiPurger.BaseURL,
		c.AkamaiPurger.ClientToken,
		c.AkamaiPurger.ClientSecret,
		c.AkamaiPurger.AccessToken,
		c.AkamaiPurger.V3Network,
		c.AkamaiPurger.PurgeRetries,
		c.AkamaiPurger.PurgeRetryBackoff.Duration,
		logger,
		scope,
	)
	cmd.FailOnError(err, "Failed to setup Akamai CCU client")

	ap := akamaiPurger{
		client: ccu,
		log:    logger,
	}

	go func() {
		t := time.NewTicker(c.AkamaiPurger.PurgeInterval.Duration)
		for {
			select {
			case <-t.C:
				ap.purge()
			}
		}
	}()

	serverMetrics := bgrpc.NewServerMetrics(scope)
	grpcSrv, l, err := bgrpc.NewServer(c.AkamaiPurger.GRPC, tlsConfig, serverMetrics, clk)
	cmd.FailOnError(err, "Unable to setup Akamai purger gRPC server")
	akamaipb.RegisterAkamaiPurgerServer(grpcSrv, &ap)

	go cmd.CatchSignals(logger, grpcSrv.GracefulStop)

	err = cmd.FilterShutdownErrors(grpcSrv.Serve(l))
	cmd.FailOnError(err, "Akamai purger gRPC service failed")
}
