package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jmhodges/clock"
	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/bdns"
	caPB "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/policy"
	pubPB "github.com/letsencrypt/boulder/publisher/proto"
	"github.com/letsencrypt/boulder/ra"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/rpc"
)

const clientName = "RA"

type config struct {
	RA struct {
		cmd.ServiceConfig
		cmd.HostnamePolicyConfig

		RateLimitPoliciesFilename string

		MaxConcurrentRPCServerRequests int64

		MaxContactsPerRegistration int

		// UseIsSafeDomain determines whether to call VA.IsSafeDomain
		UseIsSafeDomain bool // TODO: remove after va IsSafeDomain deploy

		// The number of times to try a DNS query (that has a temporary error)
		// before giving up. May be short-circuited by deadlines. A zero value
		// will be turned into 1.
		DNSTries int

		VAService        *cmd.GRPCClientConfig
		CAService        *cmd.GRPCClientConfig
		PublisherService *cmd.GRPCClientConfig

		MaxNames     int
		DoNotForceCN bool

		// Controls behaviour of the RA when asked to create a new authz for
		// a name/regID that already has a valid authz. False preserves historic
		// behaviour and ignores the existing authz and creates a new one. True
		// instructs the RA to reuse the previously created authz in lieu of
		// creating another.
		ReuseValidAuthz bool

		// AuthorizationLifetimeDays defines how long authorizations will be
		// considered valid for. Given a value of 300 days when used with a 90-day
		// cert lifetime, this allows creation of certs that will cover a whole
		// year, plus a grace period of a month.
		AuthorizationLifetimeDays int

		// PendingAuthorizationLifetimeDays defines how long authorizations may be in
		// the pending state. If you can't respond to a challenge this quickly, then
		// you need to request a new challenge.
		PendingAuthorizationLifetimeDays int

		Features map[string]bool
	}

	PA cmd.PAConfig

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

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	err = features.Set(c.RA.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	stats, logger := cmd.StatsAndLogging(c.Statsd, c.Syslog)
	scope := metrics.NewStatsdScope(stats, "RA")
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString(clientName))

	// Validate PA config and set defaults if needed
	cmd.FailOnError(c.PA.CheckChallenges(), "Invalid PA configuration")

	pa, err := policy.New(c.PA.Challenges)
	cmd.FailOnError(err, "Couldn't create PA")

	if c.RA.HostnamePolicyFile == "" {
		cmd.FailOnError(fmt.Errorf("HostnamePolicyFile must be provided."), "")
	}
	err = pa.SetHostnamePolicyFile(c.RA.HostnamePolicyFile)
	cmd.FailOnError(err, "Couldn't load hostname policy file")

	amqpConf := c.RA.AMQP
	var vac core.ValidationAuthority
	if c.RA.VAService != nil {
		conn, err := bgrpc.ClientSetup(c.RA.VAService, scope)
		cmd.FailOnError(err, "Unable to create VA client")
		vac = bgrpc.NewValidationAuthorityGRPCClient(conn)
	} else {
		vac, err = rpc.NewValidationAuthorityClient(clientName, amqpConf, scope)
		cmd.FailOnError(err, "Unable to create VA client")
	}

	var cac core.CertificateAuthority
	if c.RA.CAService != nil {
		conn, err := bgrpc.ClientSetup(c.RA.CAService, scope)
		cmd.FailOnError(err, "Unable to create CA client")
		cac = bgrpc.NewCertificateAuthorityClient(caPB.NewCertificateAuthorityClient(conn), c.RA.CAService.Timeout.Duration)
	} else {
		cac, err = rpc.NewCertificateAuthorityClient(clientName, amqpConf, scope)
		cmd.FailOnError(err, "Unable to create CA client")
	}

	var pubc core.Publisher
	if c.RA.PublisherService != nil {
		conn, err := bgrpc.ClientSetup(c.RA.PublisherService, scope)
		cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to Publisher")
		pubc = bgrpc.NewPublisherClientWrapper(pubPB.NewPublisherClient(conn), c.RA.PublisherService.Timeout.Duration)
	}

	sac, err := rpc.NewStorageAuthorityClient(clientName, amqpConf, scope)
	cmd.FailOnError(err, "Unable to create SA client")

	// TODO(patf): remove once RA.authorizationLifetimeDays is deployed
	authorizationLifetime := 300 * 24 * time.Hour
	if c.RA.AuthorizationLifetimeDays != 0 {
		authorizationLifetime = time.Duration(c.RA.AuthorizationLifetimeDays) * 24 * time.Hour
	}

	// TODO(patf): remove once RA.pendingAuthorizationLifetimeDays is deployed
	pendingAuthorizationLifetime := 7 * 24 * time.Hour
	if c.RA.PendingAuthorizationLifetimeDays != 0 {
		pendingAuthorizationLifetime = time.Duration(c.RA.PendingAuthorizationLifetimeDays) * 24 * time.Hour
	}

	rai := ra.NewRegistrationAuthorityImpl(
		clock.Default(),
		logger,
		scope,
		c.RA.MaxContactsPerRegistration,
		goodkey.NewKeyPolicy(),
		c.RA.MaxNames,
		c.RA.DoNotForceCN,
		c.RA.ReuseValidAuthz,
		authorizationLifetime,
		pendingAuthorizationLifetime,
		pubc)

	policyErr := rai.SetRateLimitPoliciesFile(c.RA.RateLimitPoliciesFilename)
	cmd.FailOnError(policyErr, "Couldn't load rate limit policies file")
	rai.PA = pa

	raDNSTimeout, err := time.ParseDuration(c.Common.DNSTimeout)
	cmd.FailOnError(err, "Couldn't parse RA DNS timeout")
	dnsTries := c.RA.DNSTries
	if dnsTries < 1 {
		dnsTries = 1
	}
	if !c.Common.DNSAllowLoopbackAddresses {
		rai.DNSResolver = bdns.NewDNSResolverImpl(
			raDNSTimeout,
			[]string{c.Common.DNSResolver},
			nil,
			scope,
			clock.Default(),
			dnsTries)
	} else {
		rai.DNSResolver = bdns.NewTestDNSResolverImpl(
			raDNSTimeout,
			[]string{c.Common.DNSResolver},
			scope,
			clock.Default(),
			dnsTries)
	}

	rai.VA = vac
	rai.CA = cac
	rai.SA = sac

	err = rai.UpdateIssuedCountForever()
	cmd.FailOnError(err, "Updating total issuance count")

	var grpcSrv *grpc.Server
	if c.RA.GRPC != nil {
		s, l, err := bgrpc.NewServer(c.RA.GRPC, scope)
		cmd.FailOnError(err, "Unable to setup RA gRPC server")
		gw := bgrpc.NewRegistrationAuthorityServer(rai)
		rapb.RegisterRegistrationAuthorityServer(s, gw)
		go func() {
			err = s.Serve(l)
			cmd.FailOnError(err, "RA gRPC service failed")
		}()
		grpcSrv = s
	}

	ras, err := rpc.NewAmqpRPCServer(amqpConf, c.RA.MaxConcurrentRPCServerRequests, scope, logger)
	cmd.FailOnError(err, "Unable to create RA RPC server")

	go cmd.CatchSignals(logger, func() {
		ras.Stop()
		if grpcSrv != nil {
			grpcSrv.GracefulStop()
		}
	})

	err = rpc.NewRegistrationAuthorityServer(ras, rai, logger)
	cmd.FailOnError(err, "Unable to setup RA RPC server")

	go cmd.DebugServer(c.RA.DebugAddr)
	go cmd.ProfileCmd(scope)

	err = ras.Start(amqpConf)
	cmd.FailOnError(err, "Unable to run RA RPC server")
}
