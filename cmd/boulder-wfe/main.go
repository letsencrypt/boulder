// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"net/http"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/wfe"
)

func setupWFE(c cmd.Config) (rpc.RegistrationAuthorityClient, rpc.StorageAuthorityClient, chan *amqp.Error) {
	ch := cmd.AmqpChannel(c.AMQP.Server)
	closeChan := ch.NotifyClose(make(chan *amqp.Error, 1))

	rac, err := rpc.NewRegistrationAuthorityClient(c.AMQP.RA.Client, c.AMQP.RA.Server, ch)
	cmd.FailOnError(err, "Unable to create RA client")

	sac, err := rpc.NewStorageAuthorityClient(c.AMQP.SA.Client, c.AMQP.SA.Server, ch)
	cmd.FailOnError(err, "Unable to create SA client")

	return rac, sac, closeChan
}

type timedHandler struct {
	f     func(w http.ResponseWriter, r *http.Request)
	stats statsd.Statter
}

var openConnections int64 = 0

func HandlerTimer(handler http.Handler, stats statsd.Statter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cStart := time.Now()
		openConnections += 1
		stats.Gauge("HttpConnectionsOpen", openConnections, 1.0)

		handler.ServeHTTP(w, r)

		openConnections -= 1
		stats.Gauge("HttpConnectionsOpen", openConnections, 1.0)

		// (FIX: this doesn't seem to really work at catching errors...)
		state := "Success"
		for _, h := range w.Header()["Content-Type"] {
			if h == "application/problem+json" {
				state = "Error"
				break
			}
		}
		// set resp timing key based on success / failure
		stats.TimingDuration(fmt.Sprintf("HttpResponseTime.%s.%s", r.URL, state), time.Since(cStart), 1.0)
	})
}

func main() {
	app := cmd.NewAppShell("boulder-wfe")
	app.Action = func(c cmd.Config) {
		// Set up logging
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
		cmd.FailOnError(err, "Could not connect to Syslog")

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		blog.SetAuditLogger(auditlogger)

		wfe := wfe.NewWebFrontEndImpl()
		rac, sac, closeChan := setupWFE(c)
		wfe.RA = &rac
		wfe.SA = &sac
		wfe.Stats = stats
		wfe.SubscriberAgreementURL = c.SubscriberAgreementURL

		wfe.IssuerCert, err = cmd.LoadCert(c.CA.IssuerCert)
		cmd.FailOnError(err, fmt.Sprintf("Couldn't read issuer cert [%s]", c.CA.IssuerCert))

		go cmd.ProfileCmd("WFE", stats)

		go func() {
			// sit around and reconnect to AMQP if the channel
			// drops for some reason and repopulate the wfe object
			// with new RA and SA rpc clients.
			for {
				for err := range closeChan {
					auditlogger.Warning(fmt.Sprintf("AMQP Channel closed, will reconnect in 5 seconds: [%s]", err))
					time.Sleep(time.Second * 5)
					rac, sac, closeChan = setupWFE(c)
					wfe.RA = &rac
					wfe.SA = &sac
					auditlogger.Warning("Reconnected to AMQP")
				}
			}
		}()

		// Set up paths
		wfe.BaseURL = c.WFE.BaseURL
		wfe.HandlePaths()

		// Add HandlerTimer to output resp time + success/failure stats to statsd
		err = http.ListenAndServe(c.WFE.ListenAddress, HandlerTimer(http.DefaultServeMux, stats))
		cmd.FailOnError(err, "Error starting HTTP server")
	}

	app.Run()
}
