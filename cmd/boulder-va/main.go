package main

import (
	"flag"
	"os"
	"time"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cdr"
	"github.com/letsencrypt/boulder/cmd"
	caaPB "github.com/letsencrypt/boulder/cmd/caa-checker/proto"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/va"
)

const clientName = "VA"

type config struct {
	VA struct {
		cmd.ServiceConfig

		UserAgent string

		IssuerDomain string

		PortConfig cmd.PortConfig

		MaxConcurrentRPCServerRequests int64

		LookupIPv6 bool

		GoogleSafeBrowsing *cmd.GoogleSafeBrowsingConfig

		CAAService *cmd.GRPCClientConfig

		CAADistributedResolver *cmd.CAADistributedResolverConfig

		// The number of times to try a DNS query (that has a temporary error)
		// before giving up. May be short-circuited by deadlines. A zero value
		// will be turned into 1.
		DNSTries int
	}

	Statsd cmd.StatsdConfig

	Syslog cmd.SyslogConfig

	Common struct {
		DNSResolver               string
		DNSTimeout                string
		DNSAllowLoopbackAddresses bool
	}
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var cfg config
	err := cmd.ReadJSONFile(*configFile, &cfg)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	go cmd.DebugServer(cfg.VA.DebugAddr)

	stats, logger := cmd.StatsAndLogging(cfg.Statsd, cfg.Syslog)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString(clientName))

	go cmd.ProfileCmd("VA", stats)

	pc := &cmd.PortConfig{
		HTTPPort:  80,
		HTTPSPort: 443,
		TLSPort:   443,
	}
	if cfg.VA.PortConfig.HTTPPort != 0 {
		pc.HTTPPort = cfg.VA.PortConfig.HTTPPort
	}
	if cfg.VA.PortConfig.HTTPSPort != 0 {
		pc.HTTPSPort = cfg.VA.PortConfig.HTTPSPort
	}
	if cfg.VA.PortConfig.TLSPort != 0 {
		pc.TLSPort = cfg.VA.PortConfig.TLSPort
	}

	var caaClient caaPB.CAACheckerClient
	if cfg.VA.CAAService != nil {
		conn, err := bgrpc.ClientSetup(cfg.VA.CAAService)
		cmd.FailOnError(err, "Failed to load credentials and create connection to service")
		caaClient = caaPB.NewCAACheckerClient(conn)
	}

	scoped := metrics.NewStatsdScope(stats, "VA", "DNS")
	sbc := newGoogleSafeBrowsing(cfg.VA.GoogleSafeBrowsing)

	var cdrClient *cdr.CAADistributedResolver
	if cfg.VA.CAADistributedResolver != nil {
		var err error
		cdrClient, err = cdr.New(
			scoped,
			cfg.VA.CAADistributedResolver.Timeout.Duration,
			cfg.VA.CAADistributedResolver.MaxFailures,
			cfg.VA.CAADistributedResolver.Proxies,
			logger)
		cmd.FailOnError(err, "Failed to create CAADistributedResolver")
	}

	dnsTimeout, err := time.ParseDuration(cfg.Common.DNSTimeout)
	cmd.FailOnError(err, "Couldn't parse DNS timeout")
	dnsTries := cfg.VA.DNSTries
	if dnsTries < 1 {
		dnsTries = 1
	}
	clk := clock.Default()
	var resolver bdns.DNSResolver
	if !cfg.Common.DNSAllowLoopbackAddresses {
		r := bdns.NewDNSResolverImpl(dnsTimeout, []string{cfg.Common.DNSResolver}, scoped, clk, dnsTries)
		r.LookupIPv6 = cfg.VA.LookupIPv6
		resolver = r
	} else {
		r := bdns.NewTestDNSResolverImpl(dnsTimeout, []string{cfg.Common.DNSResolver}, scoped, clk, dnsTries)
		r.LookupIPv6 = cfg.VA.LookupIPv6
		resolver = r
	}

	vai := va.NewValidationAuthorityImpl(
		pc,
		sbc,
		caaClient,
		cdrClient,
		resolver,
		cfg.VA.UserAgent,
		cfg.VA.IssuerDomain,
		stats,
		clk,
		logger)

	amqpConf := cfg.VA.AMQP
	if cfg.VA.GRPC != nil {
		s, l, err := bgrpc.NewServer(cfg.VA.GRPC, metrics.NewStatsdScope(stats, "VA"))
		cmd.FailOnError(err, "Unable to setup VA gRPC server")
		err = bgrpc.RegisterValidationAuthorityGRPCServer(s, vai)
		cmd.FailOnError(err, "Unable to register VA gRPC server")
		go func() {
			err = s.Serve(l)
			cmd.FailOnError(err, "VA gRPC service failed")
		}()
	}

	vas, err := rpc.NewAmqpRPCServer(amqpConf, cfg.VA.MaxConcurrentRPCServerRequests, stats, logger)
	cmd.FailOnError(err, "Unable to create VA RPC server")
	err = rpc.NewValidationAuthorityServer(vas, vai)
	cmd.FailOnError(err, "Unable to setup VA RPC server")

	err = vas.Start(amqpConf)
	cmd.FailOnError(err, "Unable to run VA RPC server")
}
