// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"

	"github.com/letsencrypt/boulder/ca"
	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
)

func main() {
	app := cmd.NewAppShell("boulder-ca")
	app.Action = func(c cmd.Config) {
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		// Set up logging
		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
		cmd.FailOnError(err, "Could not connect to Syslog")

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		blog.SetAuditLogger(auditlogger)

		go cmd.DebugServer(c.CA.DebugAddr)

		cadb, err := ca.NewCertificateAuthorityDatabaseImpl(c.CA.DBDriver, c.CA.DBConnect)

		cmd.FailOnError(err, "Failed to create CA database")

		if c.SQL.CreateTables {
			err = cadb.CreateTablesIfNotExists()
			cmd.FailOnError(err, "Failed to create CA tables")
		}

		cai, err := ca.NewCertificateAuthorityImpl(cadb, c.CA, c.Common.IssuerCert)
		cmd.FailOnError(err, "Failed to create CA impl")
		cai.MaxKeySize = c.Common.MaxKeySize

		go cmd.ProfileCmd("CA", stats)

		connectionHandler := func(ch *amqp.Channel) *rpc.AmqpRPCServer {
			saRPC, err := rpc.NewAmqpRPCClient("CA->SA", c.AMQP.SA.Server, ch)
			cmd.FailOnError(err, "Unable to create RPC client")

			sac, err := rpc.NewStorageAuthorityClient(saRPC)
			cmd.FailOnError(err, "Failed to create SA client")

			cai.SA = &sac

			cas := rpc.NewAmqpRPCServer(c.AMQP.CA.Server, ch)

			err = rpc.NewCertificateAuthorityServer(cas, cai)
			cmd.FailOnError(err, "Unable to create CA server")

			return cas
		}

		auditlogger.Info(app.VersionString())
		err = cmd.RunUntilSignaled(connectionHandler, c, auditlogger)
		cmd.FailOnError(err, "Unable to run CA RPC server")
	}

	app.Run()
}
