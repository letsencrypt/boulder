package notmain

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/honeycombio/beeline-go"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/letsencrypt/boulder/akamai"
	akamaipb "github.com/letsencrypt/boulder/akamai/proto"
	"github.com/letsencrypt/boulder/cmd"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
)

type config struct {
	AkamaiPurger struct {
		cmd.ServiceConfig

		// PurgeInterval is how often we will send a purge request
		PurgeInterval cmd.ConfigDuration

		BaseURL           string
		ClientToken       string
		ClientSecret      string
		AccessToken       string
		V3Network         string
		PurgeRetries      int
		PurgeRetryBackoff cmd.ConfigDuration
	}
	Syslog  cmd.SyslogConfig
	Beeline cmd.BeelineConfig
}

type akamaiPurger struct {
	akamaipb.UnimplementedAkamaiPurgerServer
	mu      sync.Mutex
	toPurge []string

	client *akamai.CachePurgeClient
	log    blog.Logger
}

func (ap *akamaiPurger) len() int {
	ap.mu.Lock()
	defer ap.mu.Unlock()
	return len(ap.toPurge)
}

func (ap *akamaiPurger) purge() error {
	ap.mu.Lock()
	urls := ap.toPurge[:]
	ap.toPurge = []string{}
	ap.mu.Unlock()
	if len(urls) == 0 {
		return nil
	}

	if err := ap.client.Purge(urls); err != nil {
		// Add the URLs back to the queue
		ap.mu.Lock()
		ap.toPurge = append(urls, ap.toPurge...)
		ap.mu.Unlock()
		ap.log.Errf("Failed to purge %d URLs: %s", len(urls), err)
		return err
	}
	return nil
}

// maxQueueSize is used to reject Purge requests if the queue contains
// >= the number of URLs to purge so that it can catch up.
var maxQueueSize = 1000000

func (ap *akamaiPurger) Purge(ctx context.Context, req *akamaipb.PurgeRequest) (*emptypb.Empty, error) {
	ap.mu.Lock()
	defer ap.mu.Unlock()
	if len(ap.toPurge) >= maxQueueSize {
		return nil, errors.New("Akamai purge queue too large")
	}
	ap.toPurge = append(ap.toPurge, req.Urls...)
	return &emptypb.Empty{}, nil
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

	bc, err := c.Beeline.Load()
	cmd.FailOnError(err, "Failed to load Beeline config")
	beeline.Init(bc)
	defer beeline.Close()

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

	var gaugePurgeQueueLength = prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "ccu_purge_queue_length",
			Help: "The length of the akamai-purger queue. Captured on each prometheus scrape.",
		},
		func() float64 { return float64(ap.len()) },
	)
	scope.MustRegister(gaugePurgeQueueLength)

	stop, stopped := make(chan bool, 1), make(chan bool, 1)
	ticker := time.NewTicker(c.AkamaiPurger.PurgeInterval.Duration)
	go func() {
	loop:
		for {
			select {
			case <-ticker.C:
				_ = ap.purge()
			case <-stop:
				break loop
			}
		}
		// As we may have missed a tick by calling ticker.Stop() and
		// writing to the stop channel call ap.purge one last time just
		// in case there is anything that still needs to be purged.
		if queueLen := ap.len(); queueLen > 0 {
			logger.Info(fmt.Sprintf("Shutting down; purging %d queue entries before exit.", queueLen))
			if err := ap.purge(); err != nil {
				cmd.Fail(fmt.Sprintf("Shutting down; failed to purge %d queue entries before exit: %s",
					queueLen, err))
			} else {
				logger.Info(fmt.Sprintf("Shutting down; finished purging %d queue entries.", queueLen))
			}
		} else {
			logger.Info("Shutting down; queue is already empty.")
		}
		stopped <- true
	}()

	serverMetrics := bgrpc.NewServerMetrics(scope)
	grpcSrv, l, err := bgrpc.NewServer(c.AkamaiPurger.GRPC, tlsConfig, serverMetrics, clk)
	cmd.FailOnError(err, "Unable to setup Akamai purger gRPC server")
	akamaipb.RegisterAkamaiPurgerServer(grpcSrv, &ap)
	hs := health.NewServer()
	healthpb.RegisterHealthServer(grpcSrv, hs)

	go cmd.CatchSignals(logger, func() {
		hs.Shutdown()
		grpcSrv.GracefulStop()
		// Stop the ticker and signal that we want to shutdown by writing to the
		// stop channel. We wait 15 seconds for any remaining URLs to be emptied
		// from the current queue, if we pass that deadline we exit early.
		ticker.Stop()
		stop <- true
		select {
		case <-time.After(time.Second * 15):
			cmd.Fail("Timed out waiting for purger to finish work")
		case <-stopped:
		}
	})

	err = cmd.FilterShutdownErrors(grpcSrv.Serve(l))
	cmd.FailOnError(err, "Akamai purger gRPC service failed")
	// When we get a SIGTERM, we will exit from grpcSrv.Serve as soon as all
	// extant RPCs have been processed, but we want the process to stick around
	// while we still have a goroutine purging the last elements from the queue.
	// Once that's done, CatchSignals will call os.Exit().
	select {}
}

func init() {
	cmd.RegisterCommand("akamai-purger", main)
}
