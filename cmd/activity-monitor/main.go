// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

// The Activity Monitor executable starts one or more Boulder Analysis
// Engines which monitor all AMQP communications across the message
// broker to look for anomalies.

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

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

type timings struct {
	deliveryTimings map[string]time.Time
	dtMu            sync.Mutex

	stats statsd.Statter
}

func (t *timings) size() int {
	t.dtMu.Lock()
	defer t.dtMu.Unlock()
	return len(t.deliveryTimings)
}

func (t *timings) get(id string) time.Time {
	t.dtMu.Lock()
	defer t.dtMu.Unlock()
	return t.deliveryTimings[id]
}

func (t *timings) add(id string) {
	t.dtMu.Lock()
	defer t.dtMu.Unlock()
	t.deliveryTimings[id] = time.Now()
}

func (t *timings) delete(id string) {
	t.dtMu.Lock()
	defer t.dtMu.Unlock()
	delete(t.deliveryTimings, id)
}

func (t *timings) timeDelivery(d amqp.Delivery) {
	// If d is a call add to deliveryTimings and increment openCalls, if it is a
	// response then get time.Since original call from deliveryTiming, send timing metric, and
	// decrement openCalls, in both cases send the gauge RpcCallsWaiting and increment the counter
	// RpcTraffic with the byte length of the RPC body.
	t.stats.Inc("RPC.Traffic", int64(len(d.Body)), 1.0)
	t.stats.Gauge("RPC.CallsWaiting", int64(t.size()), 1.0)

	if d.ReplyTo != "" {
		t.add(fmt.Sprintf("%s:%s", d.CorrelationId, d.ReplyTo))
	} else {
		rpcSent := t.get(fmt.Sprintf("%s:%s", d.CorrelationId, d.RoutingKey))
		if rpcSent != *new(time.Time) {
			respTime := time.Since(rpcSent)
			t.delete(fmt.Sprintf("%s:%s", d.CorrelationId, d.RoutingKey))

			// Check if the call failed
			state := "Success"
			var resp struct {
				Error rpc.RPCError
			}
			json.Unmarshal(d.Body, &resp)
			if resp.Error.Value != "" {
				state = "Error"
			}
			t.stats.Inc(fmt.Sprintf("RPC.Rate.%s", state), 1, 1.0)
			t.stats.TimingDuration(fmt.Sprintf("RPC.ResponseTime.%s.%s", d.Type, state), respTime, 1.0)
		} else {
		}
	}

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

	timings := timings{
		deliveryTimings: make(map[string]time.Time),
		stats:           stats,
	}

	// Run forever.
	for d := range deliveries {
		go timings.timeDelivery(d)

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
