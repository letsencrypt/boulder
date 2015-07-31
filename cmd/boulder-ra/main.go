// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"
	"github.com/letsencrypt/boulder/core"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/ra"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/wfe"
)

func main() {
	app := cmd.NewAppShell("boulder-ra")
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

		rai := ra.NewRegistrationAuthorityImpl()
		rai.AuthzBase = c.Common.BaseURL + wfe.AuthzPath
		rai.MaxKeySize = c.Common.MaxKeySize
		raDNSTimeout, err := time.ParseDuration(c.Common.DNSTimeout)
		cmd.FailOnError(err, "Couldn't parse RA DNS timeout")
		rai.DNSResolver = core.NewDNSResolverImpl(raDNSTimeout, []string{c.Common.DNSResolver})

		go cmd.ProfileCmd("RA", stats)

		for {
			ch, err := cmd.AmqpChannel(c)
			cmd.FailOnError(err, "Could not connect to AMQP")

			closeChan := ch.NotifyClose(make(chan *amqp.Error, 1))

			vaRPC, err := rpc.NewAmqpRPCClient("RA->VA", c.AMQP.VA.Server, ch)
			cmd.FailOnError(err, "Unable to create RPC client")

			caRPC, err := rpc.NewAmqpRPCClient("RA->CA", c.AMQP.CA.Server, ch)
			cmd.FailOnError(err, "Unable to create RPC client")

			saRPC, err := rpc.NewAmqpRPCClient("RA->SA", c.AMQP.SA.Server, ch)
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

			ras := rpc.NewAmqpRPCServer(c.AMQP.RA.Server, ch)

			err = rpc.NewRegistrationAuthorityServer(ras, &rai)
			cmd.FailOnError(err, "Unable to create RA server")

			auditlogger.Info(app.VersionString())

			cmd.RunUntilSignaled(auditlogger, ras, closeChan)
		}

	}

	app.Run()
}
