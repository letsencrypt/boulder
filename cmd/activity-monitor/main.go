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
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"
	"github.com/letsencrypt/boulder/rpc"

	"github.com/letsencrypt/boulder/analysis"
	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
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

var openCalls int64

func timeDelivery(d amqp.Delivery, stats statsd.Statter, deliveryTimings map[string]time.Time) {
	// If d is a call add to deliveryTimings and increment openCalls, if it is a
	// response then get time.Since original call from deliveryTiming, send timing metric, and
	// decrement openCalls, in both cases send the gauges RpcCallsOpen and RpcBodySize
	if d.ReplyTo != "" {
		openCalls++
		deliveryTimings[fmt.Sprintf("%s:%s", d.CorrelationId, d.ReplyTo)] = time.Now()
	} else {
		openCalls--
		rpcSent := deliveryTimings[fmt.Sprintf("%s:%s", d.CorrelationId, d.RoutingKey)]
		if rpcSent != *new(time.Time) {
			respTime := time.Since(rpcSent)
			delete(deliveryTimings, fmt.Sprintf("%s:%s", d.CorrelationId, d.RoutingKey))

			stats.TimingDuration(fmt.Sprintf("RpcCallTime.%s", d.Type), respTime, 1.0)
		}
	}

	stats.Gauge("RpcCallsOpen", openCalls, 1.0)
	stats.Gauge("RpcBodySize", int64(len(d.Body)), 1.0)
}

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

	deliveryTimings := make(map[string]time.Time)

	// Run forever.
	for d := range deliveries {
		timeDelivery(d, stats, deliveryTimings)

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

	app.Action = func(c cmd.Config) {
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)

		cmd.FailOnError(err, "Could not connect to statsd")

		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)

		cmd.FailOnError(err, "Could not connect to Syslog")

		blog.SetAuditLogger(auditlogger)

		go cmd.DebugServer(c.ActivityMonitor.DebugAddr)

		ch, err := rpc.AmqpChannel(c)

		cmd.FailOnError(err, "Could not connect to AMQP")

		go cmd.ProfileCmd("AM", stats)

		auditlogger.Info(app.VersionString())

		startMonitor(ch, auditlogger, stats)
	}

	app.Run()
}
