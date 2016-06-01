package main

import (
	"fmt"
	"time"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/ra"
	"github.com/letsencrypt/boulder/ratelimit"
	"github.com/letsencrypt/boulder/rpc"
)

const clientName = "RA"

func main() {
	app := cmd.NewAppShell("boulder-ra", "Handles service orchestration")
	app.Action = func(c cmd.Config, stats metrics.Statter, logger blog.Logger) {
		// Validate PA config and set defaults if needed
		cmd.FailOnError(c.PA.CheckChallenges(), "Invalid PA configuration")

		go cmd.DebugServer(c.RA.DebugAddr)

		pa, err := policy.New(c.PA.Challenges)
		cmd.FailOnError(err, "Couldn't create PA")

		if c.RA.HostnamePolicyFile == "" {
			cmd.FailOnError(fmt.Errorf("HostnamePolicyFile must be provided."), "")
		}
		err = pa.SetHostnamePolicyFile(c.RA.HostnamePolicyFile)
		cmd.FailOnError(err, "Couldn't load hostname policy file")

		rateLimitPolicies, err := ratelimit.LoadRateLimitPolicies(c.RA.RateLimitPoliciesFilename)
		cmd.FailOnError(err, "Couldn't load rate limit policies file")

		go cmd.ProfileCmd("RA", stats)

		amqpConf := c.RA.AMQP
		var vac core.ValidationAuthority
		if c.RA.VAService != nil {
			conn, err := bgrpc.ClientSetup(c.RA.VAService)
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

		var dc *ra.DomainCheck
		if c.RA.UseIsSafeDomain {
			dc = &ra.DomainCheck{VA: vac}
		}

		rai := ra.NewRegistrationAuthorityImpl(clock.Default(), logger, stats,
			dc, rateLimitPolicies, c.RA.MaxContactsPerRegistration, c.KeyPolicy(),
			c.RA.UseNewVARPC, c.RA.MaxNames, c.RA.DoNotForceCN)
		rai.PA = pa
		raDNSTimeout, err := time.ParseDuration(c.Common.DNSTimeout)
		cmd.FailOnError(err, "Couldn't parse RA DNS timeout")
		scoped := metrics.NewStatsdScope(stats, "RA", "DNS")
		dnsTries := c.RA.DNSTries
		if dnsTries < 1 {
			dnsTries = 1
		}
		if !c.Common.DNSAllowLoopbackAddresses {
			rai.DNSResolver = bdns.NewDNSResolverImpl(raDNSTimeout, []string{c.Common.DNSResolver}, scoped, clock.Default(), dnsTries)
		} else {
			rai.DNSResolver = bdns.NewTestDNSResolverImpl(raDNSTimeout, []string{c.Common.DNSResolver}, scoped, clock.Default(), dnsTries)
		}

		rai.VA = vac
		rai.CA = cac
		rai.SA = sac

		ras, err := rpc.NewAmqpRPCServer(amqpConf, c.RA.MaxConcurrentRPCServerRequests, stats)
		cmd.FailOnError(err, "Unable to create RA RPC server")
		err = rpc.NewRegistrationAuthorityServer(ras, rai)
		cmd.FailOnError(err, "Unable to setup RA RPC server")

		err = ras.Start(amqpConf)
		cmd.FailOnError(err, "Unable to run RA RPC server")
	}

	app.Run()
}
