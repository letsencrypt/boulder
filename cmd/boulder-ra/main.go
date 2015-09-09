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
	"github.com/letsencrypt/boulder/wfe"
)

func main() {
	app := cmd.NewAppShell("boulder-ra", "Handles service orchestration")
	app.Action = func(c cmd.Config) {
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		// Set up logging
		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
		cmd.FailOnError(err, "Could not connect to Syslog")

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		blog.SetAuditLogger(auditlogger)

		go cmd.DebugServer(c.RA.DebugAddr)

		paDbMap, err := sa.NewDbMap(c.PA.DBConnect)
		cmd.FailOnError(err, "Couldn't connect to policy database")
		pa, err := policy.NewPolicyAuthorityImpl(paDbMap, c.PA.EnforcePolicyWhitelist)
		cmd.FailOnError(err, "Couldn't create PA")

		rai := ra.NewRegistrationAuthorityImpl(clock.Default(), auditlogger)
		rai.AuthzBase = c.Common.BaseURL + wfe.AuthzPath
		rai.MaxKeySize = c.Common.MaxKeySize
		rai.PA = pa
		raDNSTimeout, err := time.ParseDuration(c.Common.DNSTimeout)
		cmd.FailOnError(err, "Couldn't parse RA DNS timeout")
		if !c.Common.DNSAllowLoopbackAddresses {
			rai.DNSResolver = core.NewDNSResolverImpl(raDNSTimeout, []string{c.Common.DNSResolver})
		} else {
			rai.DNSResolver = core.NewTestDNSResolverImpl(raDNSTimeout, []string{c.Common.DNSResolver})
		}

		go cmd.ProfileCmd("RA", stats)

		connectionHandler := func(srv *rpc.AmqpRPCServer) {
			vaRPC, err := rpc.NewAmqpRPCClient("RA->VA", c.AMQP.VA.Server, srv.Channel)
			cmd.FailOnError(err, "Unable to create RPC client")

			caRPC, err := rpc.NewAmqpRPCClient("RA->CA", c.AMQP.CA.Server, srv.Channel)
			cmd.FailOnError(err, "Unable to create RPC client")

			saRPC, err := rpc.NewAmqpRPCClient("RA->SA", c.AMQP.SA.Server, srv.Channel)
			cmd.FailOnError(err, "Unable to create RPC client")

			vac, err := rpc.NewValidationAuthorityClient(vaRPC)
			cmd.FailOnError(err, "Unable to create VA client")

			cac, err := rpc.NewCertificateAuthorityClient(caRPC)
			cmd.FailOnError(err, "Unable to create CA client")

			sac, err := rpc.NewStorageAuthorityClient(saRPC)
			cmd.FailOnError(err, "Unable to create SA client")

			rai.VA = &vac
			rai.CA = &cac
			rai.SA = &sac
		}

		ras, err := rpc.NewAmqpRPCServer(c.AMQP.RA.Server, connectionHandler)
		cmd.FailOnError(err, "Unable to create RA RPC server")
		rpc.NewRegistrationAuthorityServer(ras, &rai)

		auditlogger.Info(app.VersionString())

		err = ras.Start(c)
		cmd.FailOnError(err, "Unable to run RA RPC server")
	}

	app.Run()
}
