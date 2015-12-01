// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

// The Activity Monitor executable starts one or more Boulder Analysis
// Engines which monitor all AMQP communications across the message
// broker to look for anomalies.

import (
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"

	"github.com/letsencrypt/boulder/analysis"
	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
)

func main() {
	app := cmd.NewAppShell("activity-monitor", "RPC activity monitor")

	app.Action = func(c cmd.Config, stats statsd.Statter, auditlogger *blog.AuditLogger) {
		go cmd.DebugServer(c.ActivityMonitor.DebugAddr)

		amqpConf := c.ActivityMonitor.AMQP
		server, err := rpc.NewAmqpRPCServer(amqpConf, 0, stats)
		cmd.FailOnError(err, "Could not connect to AMQP")

		ae := analysisengine.NewLoggingAnalysisEngine()
		server.HandleDeliveries(rpc.DeliveryHandler(func(d amqp.Delivery) {
			ae.ProcessMessage(d)
		}))

		go cmd.ProfileCmd("AM", stats)

		err = server.Start(amqpConf)
		cmd.FailOnError(err, "Unable to run Activity Monitor")
	}

	app.Run()
}
