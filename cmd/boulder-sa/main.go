// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"
)

func main() {
	app := cmd.NewAppShell("boulder-sa", "Handles SQL operations")
	app.Action = func(c cmd.Config, stats metrics.Statter, auditlogger *blog.AuditLogger) {
		saConf := c.SA
		go cmd.DebugServer(saConf.DebugAddr)

		dbURL, err := saConf.DBConfig.URL()
		cmd.FailOnError(err, "Couldn't load DB URL")
		dbMap, err := sa.NewDbMap(dbURL)
		cmd.FailOnError(err, "Couldn't connect to SA database")

		sai, err := sa.NewSQLStorageAuthority(dbMap, clock.Default(), auditlogger)
		cmd.FailOnError(err, "Failed to create SA impl")

		go cmd.ProfileCmd("SA", stats)

		amqpConf := saConf.AMQP
		sas, err := rpc.NewAmqpRPCServer(amqpConf, c.SA.MaxConcurrentRPCServerRequests, stats)
		cmd.FailOnError(err, "Unable to create SA RPC server")
		rpc.NewStorageAuthorityServer(sas, sai)

		err = sas.Start(amqpConf)
		cmd.FailOnError(err, "Unable to run SA RPC server")
	}

	app.Run()
}
