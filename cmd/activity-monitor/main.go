// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

// The Activity Monitor executable starts one or more Boulder Analysis
// Engines which monitor all AMQP communications across the message
// broker to look for anomalies.

import (
	"fmt"
	"os"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"

	"github.com/letsencrypt/boulder/analysis"
	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
)

// Constants for AMQP
const (
	QueueName        = "Monitor"
	AmqpExchange     = "boulder"
	AmqpExchangeType = "topic"
	AmqpInternal     = false
	AmqpDurable      = false
	AmqpDeleteUnused = false
	AmqpExclusive    = false
	AmqpNoWait       = false
	AmqpNoLocal      = false
	AmqpAutoAck      = false
	AmqpMandatory    = false
	AmqpImmediate    = false
)

func startMonitor(rpcCh *amqp.Channel, logger *blog.AuditLogger, stats statsd.Statter) {
	ae := analysisengine.NewLoggingAnalysisEngine()

	// For convenience at the broker, identifiy ourselves by hostname
	consumerTag, err := os.Hostname()
	if err != nil {
		cmd.FailOnError(err, "Could not determine hostname")
	}

	_, err = rpcCh.QueueDeclarePassive(
		QueueName,
		AmqpDurable,
		AmqpDeleteUnused,
		AmqpExclusive,
		AmqpNoWait,
		nil)
	if err != nil {
		logger.Info(fmt.Sprintf("Queue %s does not exist on AMQP server, attempting to create.", QueueName))

		// Attempt to create the Queue if not exists
		_, err = rpcCh.QueueDeclare(
			QueueName,
			AmqpDurable,
			AmqpDeleteUnused,
			AmqpExclusive,
			AmqpNoWait,
			nil)
		if err != nil {
			cmd.FailOnError(err, "Could not declare queue")
		}

		routingKey := "#" //wildcard

		err = rpcCh.QueueBind(
			QueueName,
			routingKey,
			AmqpExchange,
			false,
			nil)
		if err != nil {
			txt := fmt.Sprintf("Could not bind to queue [%s]. NOTE: You may need to delete %s to re-trigger the bind attempt after fixing permissions, or manually bind the queue to %s.", QueueName, QueueName, routingKey)
			cmd.FailOnError(err, txt)
		}
	}

	deliveries, err := rpcCh.Consume(
		QueueName,
		consumerTag,
		AmqpAutoAck,
		AmqpExclusive,
		AmqpNoLocal,
		AmqpNoWait,
		nil)
	if err != nil {
		cmd.FailOnError(err, "Could not subscribe to queue")
	}

	// Run forever.
	for d := range deliveries {
		// Pass each message to the Analysis Engine
		err = ae.ProcessMessage(d)
		if err != nil {
			logger.Alert(fmt.Sprintf("Could not process message: %s", err))
		} else {
			// Only ack the delivery we actually handled (ackMultiple=false)
			const ackMultiple = false
			d.Ack(ackMultiple)
		}
	}
}

func main() {
	app := cmd.NewAppShell("activity-monitor", "RPC activity monitor")

	app.Action = func(c cmd.Config, stats statsd.Statter, auditlogger *blog.AuditLogger) {
		go cmd.DebugServer(c.ActivityMonitor.DebugAddr)

		ch, err := rpc.AmqpChannel(c)

		cmd.FailOnError(err, "Could not connect to AMQP")

		go cmd.ProfileCmd("AM", stats)

		startMonitor(ch, auditlogger, stats)
	}

	app.Run()
}
