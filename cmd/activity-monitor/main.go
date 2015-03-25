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

	"github.com/streadway/amqp"

	"github.com/letsencrypt/boulder/analysis"
	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
)

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

func startMonitor(rpcCh *amqp.Channel, logger *blog.AuditLogger) {
	ae := analysisengine.NewLoggingAnalysisEngine(logger)

	// For convenience at the broker, identifiy ourselves by hostname
	consumerTag, err := os.Hostname()
	if err != nil {
		cmd.FailOnError(err, "Could not determine hostname")
	}

	err = rpcCh.ExchangeDeclare(
		AmqpExchange,
		AmqpExchangeType,
		AmqpDurable,
		AmqpDeleteUnused,
		AmqpInternal,
		AmqpNoWait,
		nil)
	if err != nil {
		cmd.FailOnError(err, "Could not declare exchange")
	}

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

	err = rpcCh.QueueBind(
		QueueName,
		"#", //wildcard
		AmqpExchange,
		false,
		nil)
	if err != nil {
		cmd.FailOnError(err, "Could not bind queue")
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
	app := cmd.NewAppShell("activity-monitor")

	app.Action = func(c cmd.Config) {
		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag)

		cmd.FailOnError(err, "Could not connect to Syslog")

		ch := cmd.AmqpChannel(c.AMQP.Server)

		startMonitor(ch, auditlogger)
	}

	app.Run()
}
