package main

import (
	"flag"
	"fmt"
	"time"
	"os"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/goodkey"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/ra"
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

		VAService *cmd.GRPCClientConfig

		MaxNames     int
		DoNotForceCN bool

		// Controls behaviour of the RA when asked to create a new authz for
		// a name/regID that already has a valid authz. False preserves historic
		// behaviour and ignores the existing authz and creates a new one. True
		// instructs the RA to reuse the previously created authz in lieu of
		// creating another.
		ReuseValidAuthz bool
	}

	*cmd.AllowedSigningAlgos

	cmd.StatsdConfig

	cmd.SyslogConfig

	PA cmd.PAConfig

	Common struct {
		DNSResolver               string
		DNSTimeout                string
		DNSAllowLoopbackAddresses bool
	}

}

func (cfg config) KeyPolicy() goodkey.KeyPolicy {
	if cfg.AllowedSigningAlgos != nil {
		return goodkey.KeyPolicy{
			AllowRSA:           cfg.AllowedSigningAlgos.RSA,
			AllowECDSANISTP256: cfg.AllowedSigningAlgos.ECDSANISTP256,
			AllowECDSANISTP384: cfg.AllowedSigningAlgos.ECDSANISTP384,
			AllowECDSANISTP521: cfg.AllowedSigningAlgos.ECDSANISTP521,
		}
	}
	return goodkey.KeyPolicy{
		AllowRSA: true,
	}
}

func main() {
	configFile := flag.String("config", "", "Mandatory file containing a JSON config")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var cfg config
	err := cmd.ReadJSONFile(*configFile, &cfg)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	stats, logger := cmd.StatsAndLogging(cfg.StatsdConfig, cfg.SyslogConfig)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString(clientName))

	// Validate PA config and set defaults if needed
	cmd.FailOnError(cfg.PA.CheckChallenges(), "Invalid PA configuration")

	go cmd.DebugServer(cfg.RA.DebugAddr)

	pa, err := policy.New(cfg.PA.Challenges)
	cmd.FailOnError(err, "Couldn't create PA")

	if cfg.RA.HostnamePolicyFile == "" {
		cmd.FailOnError(fmt.Errorf("HostnamePolicyFile must be provided."), "")
	}
	err = pa.SetHostnamePolicyFile(cfg.RA.HostnamePolicyFile)
	cmd.FailOnError(err, "Couldn't load hostname policy file")

	go cmd.ProfileCmd("RA", stats)

	amqpConf := cfg.RA.AMQP
	var vac core.ValidationAuthority
	if cfg.RA.VAService != nil {
		conn, err := bgrpc.ClientSetup(cfg.RA.VAService)
		cmd.FailOnError(err, "Unable to create VA client")
		vac = bgrpc.NewValidationAuthorityGRPCClient(conn)
	} else {
		vac, err = rpc.NewValidationAuthorityClient(clientName, amqpConf, stats)
		cmd.FailOnError(err, "Unable to create VA client")
	}

	cac, err := rpc.NewCertificateAuthorityClient(clientName, amqpConf, stats)
	cmd.FailOnError(err, "Unable to create CA client")

	sac, err := rpc.NewStorageAuthorityClient(clientName, amqpConf, stats)
	cmd.FailOnError(err, "Unable to create SA client")

	rai := ra.NewRegistrationAuthorityImpl(
		clock.Default(),
		logger,
		stats,
		cfg.RA.MaxContactsPerRegistration,
		cfg.KeyPolicy(),
		cfg.RA.MaxNames,
		cfg.RA.DoNotForceCN,
		cfg.RA.ReuseValidAuthz)

	policyErr := rai.SetRateLimitPoliciesFile(cfg.RA.RateLimitPoliciesFilename)
	cmd.FailOnError(policyErr, "Couldn't load rate limit policies file")
	rai.PA = pa

	raDNSTimeout, err := time.ParseDuration(cfg.Common.DNSTimeout)
	cmd.FailOnError(err, "Couldn't parse RA DNS timeout")
	scoped := metrics.NewStatsdScope(stats, "RA", "DNS")
	dnsTries := cfg.RA.DNSTries
	if dnsTries < 1 {
		dnsTries = 1
	}
	if !cfg.Common.DNSAllowLoopbackAddresses {
		rai.DNSResolver = bdns.NewDNSResolverImpl(
			raDNSTimeout,
			[]string{cfg.Common.DNSResolver},
			scoped,
			clock.Default(),
			dnsTries)
	} else {
		rai.DNSResolver = bdns.NewTestDNSResolverImpl(
			raDNSTimeout,
			[]string{cfg.Common.DNSResolver},
			scoped,
			clock.Default(),
			dnsTries)
	}

	rai.VA = vac
	rai.CA = cac
	rai.SA = sac

	ras, err := rpc.NewAmqpRPCServer(amqpConf, cfg.RA.MaxConcurrentRPCServerRequests, stats, logger)
	cmd.FailOnError(err, "Unable to create RA RPC server")
	err = rpc.NewRegistrationAuthorityServer(ras, rai, logger)
	cmd.FailOnError(err, "Unable to setup RA RPC server")

	err = ras.Start(amqpConf)
	cmd.FailOnError(err, "Unable to run RA RPC server")
}
