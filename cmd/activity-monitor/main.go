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
	"net/http"
	"encoding/json"
	"html/template"
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

type resultAt struct {
	Result int64
	At     time.Time
}

type rpcStats struct {
	RpcTimings  map[string][]resultAt
	TotalCalls  int64
	AvgCallTook []resultAt
	CPS         []resultAt
}

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
	rpcMetrics := rpcStats{RpcTimings: make(map[string][]resultAt), TotalCalls: 0}
	cps := int64(0)
	avgCallTook := int64(0)

	monitorTmpl, err := template.New("monitor").Parse(monitorHTML)
	if err != nil {
		cmd.FailOnError(err, "Couldn't load HTML template")
	}

	go func() {
		for {
			rpcMetrics.CPS = append(rpcMetrics.CPS, resultAt{Result: (cps / 5), At: time.Now()})
			rpcMetrics.AvgCallTook = append(rpcMetrics.AvgCallTook, resultAt{Result: avgCallTook, At: time.Now()})
			cps = 0
			time.Sleep(time.Second * 5)
		}
	}()

	go func() {
		http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
			jsonRpcStats, err := json.Marshal(rpcMetrics)
			if err != nil {

			}
			w.Header().Set("Access-Control-Allow-Origin", "*")
			fmt.Fprintf(w, "%+v", string(jsonRpcStats))
		})

		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			monitorTmpl.Execute(w, nil)
		})


		http.ListenAndServe(":8080", nil)
	}()

	// Run forever.
	for d := range deliveries {
		fmt.Printf("%+v\n", d)
		if d.ReplyTo != "" {
			deliveryTimings[fmt.Sprintf("%s:%s", d.CorrelationId, d.ReplyTo)] = time.Now()
		} else {
			rpcSent := deliveryTimings[fmt.Sprintf("%s:%s", d.CorrelationId, d.RoutingKey)]
			if rpcSent != *new(time.Time) {
				respTime := time.Since(rpcSent)
				delete(deliveryTimings, fmt.Sprintf("%s:%s", d.CorrelationId, d.RoutingKey))
				fmt.Printf("RPC call [%s] from [%s] took %s\n", d.Type, d.RoutingKey, respTime)
				// should probably shift into these after some limit so we don't end up with MASSIVE
				// lists in memory we don't really need...
				rpcMetrics.RpcTimings[d.Type] = append(rpcMetrics.RpcTimings[d.Type], resultAt{Result: respTime.Nanoseconds(), At: time.Now()})
				rpcMetrics.TotalCalls += 1
				avgCallTook = ((avgCallTook * (rpcMetrics.TotalCalls - 1)) + respTime.Nanoseconds()) / rpcMetrics.TotalCalls
			}
		}
		cps += 1

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
