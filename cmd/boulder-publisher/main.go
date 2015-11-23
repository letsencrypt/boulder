// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/publisher"
	"github.com/letsencrypt/boulder/rpc"
)

const clientName = "Publisher"

func main() {
	app := cmd.NewAppShell("boulder-publisher", "Submits issued certificates to CT logs")
	app.Action = func(c cmd.Config, stats statsd.Statter, auditlogger *blog.AuditLogger) {
		pubi, err := publisher.NewPublisherImpl(c.Common.CT)
		cmd.FailOnError(err, "Could not setup Publisher")

		go cmd.DebugServer(c.Publisher.DebugAddr)
		go cmd.ProfileCmd("Publisher", stats)

		amqpConf := c.Publisher.AMQP
		pubi.SA, err = rpc.NewStorageAuthorityClient(clientName, amqpConf, stats)
		cmd.FailOnError(err, "Unable to create SA client")

		pubs, err := rpc.NewAmqpRPCServer(amqpConf, c.Publisher.MaxConcurrentRPCServerRequests, stats)
		cmd.FailOnError(err, "Unable to create Publisher RPC server")
		rpc.NewPublisherServer(pubs, &pubi)

		err = pubs.Start(amqpConf)
		cmd.FailOnError(err, "Unable to run Publisher RPC server")
	}

	app.Run()
}
