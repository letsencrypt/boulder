// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/va"
)

func main() {
	app := cmd.NewAppShell("boulder-va")
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

		vai := va.NewValidationAuthorityImpl(c.CA.TestMode)
		dnsTimeout, err := time.ParseDuration(c.Common.DNSTimeout)
		cmd.FailOnError(err, "Couldn't parse DNS timeout")
		vai.DNSResolver = core.NewDNSResolverImpl(dnsTimeout, []string{c.Common.DNSResolver})
		vai.UserAgent = c.VA.UserAgent

		for {
			ch, err := cmd.AmqpChannel(c)
			cmd.FailOnError(err, "Could not connect to AMQP")

			closeChan := ch.NotifyClose(make(chan *amqp.Error, 1))

			raRPC, err := rpc.NewAmqpRPCClient("VA->RA", c.AMQP.RA.Server, ch)
			cmd.FailOnError(err, "Unable to create RPC client")

			rac, err := rpc.NewRegistrationAuthorityClient(raRPC)
			cmd.FailOnError(err, "Unable to create RA client")

			vai.RA = &rac

			vas := rpc.NewAmqpRPCServer(c.AMQP.VA.Server, ch)

			err = rpc.NewValidationAuthorityServer(vas, &vai)
			cmd.FailOnError(err, "Unable to create VA server")

			auditlogger.Info(app.VersionString())

			cmd.RunUntilSignaled(auditlogger, vas, closeChan)
		}
	}

	app.Run()
}
