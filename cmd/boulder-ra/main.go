// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/sa"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/ra"
	"github.com/letsencrypt/boulder/rpc"
)

func main() {
	app := cmd.NewAppShell("boulder-ra", "Handles service orchestration")
	app.Action = func(c cmd.Config) {
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		// Set up logging
		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
		cmd.FailOnError(err, "Could not connect to Syslog")
		auditlogger.Info(app.VersionString())

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		blog.SetAuditLogger(auditlogger)

		go cmd.DebugServer(c.RA.DebugAddr)

		paDbMap, err := sa.NewDbMap(c.PA.DBConnect)
		cmd.FailOnError(err, "Couldn't connect to policy database")
		pa, err := policy.NewPolicyAuthorityImpl(paDbMap, c.PA.EnforcePolicyWhitelist)
		cmd.FailOnError(err, "Couldn't create PA")

		rateLimitPolicies, err := cmd.LoadRateLimitPolicies(c.RA.RateLimitPoliciesFilename)
		cmd.FailOnError(err, "Couldn't load rate limit policies file")

		go cmd.ProfileCmd("RA", stats)

		vaRPC, err := rpc.NewAmqpRPCClient("RA->VA", c.AMQP.VA.Server, c, stats)
		cmd.FailOnError(err, "Unable to create RPC client")

		caRPC, err := rpc.NewAmqpRPCClient("RA->CA", c.AMQP.CA.Server, c, stats)
		cmd.FailOnError(err, "Unable to create RPC client")

		saRPC, err := rpc.NewAmqpRPCClient("RA->SA", c.AMQP.SA.Server, c, stats)
		cmd.FailOnError(err, "Unable to create RPC client")

		vac, err := rpc.NewValidationAuthorityClient(vaRPC)
		cmd.FailOnError(err, "Unable to create VA client")

		cac, err := rpc.NewCertificateAuthorityClient(caRPC)
		cmd.FailOnError(err, "Unable to create CA client")

		sac, err := rpc.NewStorageAuthorityClient(saRPC)
		cmd.FailOnError(err, "Unable to create SA client")

		var dc *ra.DomainCheck
		if c.RA.UseIsSafeDomain {
			dc = &ra.DomainCheck{&vac}
		}

		rai := ra.NewRegistrationAuthorityImpl(clock.Default(), auditlogger, stats,
			dc, rateLimitPolicies, c.RA.MaxContactsPerRegistration)
		rai.PA = pa
		raDNSTimeout, err := time.ParseDuration(c.Common.DNSTimeout)
		cmd.FailOnError(err, "Couldn't parse RA DNS timeout")
		if !c.Common.DNSAllowLoopbackAddresses {
			rai.DNSResolver = core.NewDNSResolverImpl(raDNSTimeout, []string{c.Common.DNSResolver})
		} else {
			rai.DNSResolver = core.NewTestDNSResolverImpl(raDNSTimeout, []string{c.Common.DNSResolver})
		}

		rai.VA = &vac
		rai.CA = &cac
		rai.SA = &sac

		ras, err := rpc.NewAmqpRPCServer(c.AMQP.RA.Server, c.RA.MaxConcurrentRPCServerRequests, c)
		cmd.FailOnError(err, "Unable to create RA RPC server")
		rpc.NewRegistrationAuthorityServer(ras, rai)

		err = ras.Start(c)
		cmd.FailOnError(err, "Unable to run RA RPC server")
	}

	app.Run()
}
