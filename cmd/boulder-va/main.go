// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/va"
)

func main() {
	app := cmd.NewAppShell("boulder-va", "Handles challenge validation")
	app.Action = func(c cmd.Config) {
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		// Set up logging
		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
		cmd.FailOnError(err, "Could not connect to Syslog")

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		blog.SetAuditLogger(auditlogger)

		go cmd.DebugServer(c.VA.DebugAddr)

		go cmd.ProfileCmd("VA", stats)

		pc := &va.PortConfig{
			SimpleHTTPPort:  80,
			SimpleHTTPSPort: 443,
			DVSNIPort:       443,
		}
		if c.VA.PortConfig.SimpleHTTPPort != 0 {
			pc.SimpleHTTPPort = c.VA.PortConfig.SimpleHTTPPort
		}
		if c.VA.PortConfig.SimpleHTTPSPort != 0 {
			pc.SimpleHTTPSPort = c.VA.PortConfig.SimpleHTTPSPort
		}
		if c.VA.PortConfig.DVSNIPort != 0 {
			pc.DVSNIPort = c.VA.PortConfig.DVSNIPort
		}
		vai := va.NewValidationAuthorityImpl(pc)
		dnsTimeout, err := time.ParseDuration(c.Common.DNSTimeout)
		cmd.FailOnError(err, "Couldn't parse DNS timeout")
		vai.DNSResolver = core.NewDNSResolverImpl(dnsTimeout, []string{c.Common.DNSResolver})
		vai.UserAgent = c.VA.UserAgent

		connectionHandler := func(srv *rpc.AmqpRPCServer) {
			raRPC, err := rpc.NewAmqpRPCClient("VA->RA", c.AMQP.RA.Server, srv.Channel)
			cmd.FailOnError(err, "Unable to create RPC client")

			rac, err := rpc.NewRegistrationAuthorityClient(raRPC)
			cmd.FailOnError(err, "Unable to create RA client")

			vai.RA = &rac
		}

		vas, err := rpc.NewAmqpRPCServer(c.AMQP.VA.Server, connectionHandler)
		cmd.FailOnError(err, "Unable to create VA RPC server")
		rpc.NewValidationAuthorityServer(vas, vai)

		auditlogger.Info(app.VersionString())

		err = vas.Start(c)
		cmd.FailOnError(err, "Unable to run VA RPC server")
	}

	app.Run()
}
