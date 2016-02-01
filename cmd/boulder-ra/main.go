// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/sa"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/ra"
	"github.com/letsencrypt/boulder/rpc"
)

const clientName = "RA"

func main() {
	app := cmd.NewAppShell("boulder-ra", "Handles service orchestration")
	app.Action = func(c cmd.Config, stats statsd.Statter, auditlogger *blog.AuditLogger) {
		// Validate PA config and set defaults if needed
		cmd.FailOnError(c.PA.CheckChallenges(), "Invalid PA configuration")

		go cmd.DebugServer(c.RA.DebugAddr)

		dbURL, err := c.PA.DBConfig.URL()
		cmd.FailOnError(err, "Couldn't load DB URL")
		paDbMap, err := sa.NewDbMap(dbURL)
		cmd.FailOnError(err, "Couldn't connect to policy database")
		pa, err := policy.NewPolicyAuthorityImpl(paDbMap, c.PA.EnforcePolicyWhitelist, c.PA.Challenges)
		cmd.FailOnError(err, "Couldn't create PA")

		rateLimitPolicies, err := cmd.LoadRateLimitPolicies(c.RA.RateLimitPoliciesFilename)
		cmd.FailOnError(err, "Couldn't load rate limit policies file")

		go cmd.ProfileCmd("RA", stats)

		amqpConf := c.RA.AMQP
		vac, err := rpc.NewValidationAuthorityClient(clientName, amqpConf, stats)
		cmd.FailOnError(err, "Unable to create VA client")

		cac, err := rpc.NewCertificateAuthorityClient(clientName, amqpConf, stats)
		cmd.FailOnError(err, "Unable to create CA client")

		sac, err := rpc.NewStorageAuthorityClient(clientName, amqpConf, stats)
		cmd.FailOnError(err, "Unable to create SA client")

		var dc *ra.DomainCheck
		if c.RA.UseIsSafeDomain {
			dc = &ra.DomainCheck{VA: vac}
		}

		rai := ra.NewRegistrationAuthorityImpl(clock.Default(), auditlogger, stats,
			dc, rateLimitPolicies, c.RA.MaxContactsPerRegistration, c.KeyPolicy(),
			c.RA.UseUpdateValidationRPC)
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
		rpc.NewRegistrationAuthorityServer(ras, rai)

		err = ras.Start(amqpConf)
		cmd.FailOnError(err, "Unable to run RA RPC server")
	}

	app.Run()
}
