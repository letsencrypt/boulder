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

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"
	"github.com/letsencrypt/boulder/analysis"
	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
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

// type resultAt struct {
// 	Result int64
// 	At     time.Time
// }

// type rpcStats struct {
// 	TotalCalls    int64
// 	RpcTimings    map[string][]resultAt // for short term data (tons of points)
// 	RpcAvgTimings map[string][]resultAt // for long term data (less points)
// 	AvgCallTook   []resultAt            // total avg call time
// 	CPS           []resultAt            // total calls made since monitor started
// }

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

	deliveryTimings := make(map[string]time.Time)
	stats, err := statsd.NewClient("localhost:8125", "Boulder")
	if err != nil {
		cmd.FailOnError(err, "Couldn't connect to statsd")
	}

	// Run forever.
	for d := range deliveries {
		// If d is a call add to deliveryTimings and increment Boulder.RpcOpenCalls, if it is a 
		// response then get time.Since call from deliveryTiming, send timing metric, and
		// decrement Boulder.RpcOpenCalls
		go func() {
			if d.ReplyTo != "" {
				deliveryTimings[fmt.Sprintf("%s:%s", d.CorrelationId, d.ReplyTo)] = time.Now()
				if err := stats.Inc("RpcOpenCalls", 1, 1.0); err != nil {
					logger.Alert(fmt.Sprintf("Could not increment boulder.RpcOpenCalls: %s", err))
				}
			} else {
				rpcSent := deliveryTimings[fmt.Sprintf("%s:%s", d.CorrelationId, d.RoutingKey)]
				if rpcSent != *new(time.Time) {
					respTime := time.Since(rpcSent)
					delete(deliveryTimings, fmt.Sprintf("%s:%s", d.CorrelationId, d.RoutingKey))
					
					if err := stats.Timing(fmt.Sprintf("Rpc.%s", d.Type), respTime.Nanoseconds(), 1.0); err != nil {
						logger.Alert(fmt.Sprintf("Could send timing for boulder.Rpc.%s: %s", d.Type, err))
					}
					if err := stats.Dec("RpcOpenCalls", 1, 1.0); err != nil {
						logger.Alert(fmt.Sprintf("Could not decrement boulder.RpcOpenCalls: %s", err))
					}
				}
			}
		}()

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
