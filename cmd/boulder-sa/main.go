// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"
)

func main() {
	app := cmd.NewAppShell("boulder-sa")
	app.Action = func(c cmd.Config) {
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		// Set up logging
		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
		cmd.FailOnError(err, "Could not connect to Syslog")

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		blog.SetAuditLogger(auditlogger)

		go cmd.DebugServer(c.SA.DebugAddr)

		dbMap, err := sa.NewDbMap(c.SA.DBConnect)
		cmd.FailOnError(err, "Couldn't connect to SA database")

		sai, err := sa.NewSQLStorageAuthority(dbMap)
		cmd.FailOnError(err, "Failed to create SA impl")
		sai.SetSQLDebug(c.SQL.SQLDebug)

		if c.SQL.CreateTables {
			err = sai.CreateTablesIfNotExists()
			cmd.FailOnError(err, "Failed to create tables")
		}

		go cmd.ProfileCmd("SA", stats)

		connectionHandler := func(*rpc.AmqpRPCServer) {}

		sas, err := rpc.NewAmqpRPCServer(c.AMQP.SA.Server, connectionHandler)
		cmd.FailOnError(err, "Unable to create SA RPC server")
		rpc.NewStorageAuthorityServer(sas, sai)

		auditlogger.Info(app.VersionString())

		err = sas.Start(c)
		cmd.FailOnError(err, "Unable to run SA RPC server")
	}

	app.Run()
}
