// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/wfe"
)

func setupWFE(c cmd.Config, logger *blog.AuditLogger) (rpc.RegistrationAuthorityClient, rpc.StorageAuthorityClient, chan *amqp.Error) {
	ch, err := rpc.AmqpChannel(c)
	cmd.FailOnError(err, "Could not connect to AMQP")
	logger.Info(" [!] Connected to AMQP")

	closeChan := ch.NotifyClose(make(chan *amqp.Error, 1))

	raRPC, err := rpc.NewAmqpRPCClient("WFE->RA", c.AMQP.RA.Server, ch)
	cmd.FailOnError(err, "Unable to create RPC client")

	saRPC, err := rpc.NewAmqpRPCClient("WFE->SA", c.AMQP.SA.Server, ch)
	cmd.FailOnError(err, "Unable to create RPC client")

	rac, err := rpc.NewRegistrationAuthorityClient(raRPC)
	cmd.FailOnError(err, "Unable to create RA client")

	sac, err := rpc.NewStorageAuthorityClient(saRPC)
	cmd.FailOnError(err, "Unable to create SA client")

	return rac, sac, closeChan
}

type timedHandler struct {
	f     func(w http.ResponseWriter, r *http.Request)
	stats statsd.Statter
}

var openConnections int64

// HandlerTimer monitors HTTP performance and sends the details to StatsD.
func HandlerTimer(handler http.Handler, stats statsd.Statter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cStart := time.Now()
		openConnections++
		stats.Gauge("HttpConnectionsOpen", openConnections, 1.0)

		handler.ServeHTTP(w, r)

		openConnections--
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
	addrFlag := cli.StringFlag{
		Name:   "addr",
		Value:  "",
		Usage:  "if set, overrides the listenAddr setting in the WFE config",
		EnvVar: "WFE_LISTEN_ADDR",
	}
	app.App.Flags = append(app.App.Flags, addrFlag)
	app.Config = func(c *cli.Context, config cmd.Config) cmd.Config {
		if c.GlobalString("addr") != "" {
			config.WFE.ListenAddress = c.GlobalString("addr")
		}
		return config
	}
	app.Action = func(c cmd.Config) {
		// Set up logging
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
		cmd.FailOnError(err, "Could not connect to Syslog")

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		blog.SetAuditLogger(auditlogger)

		go cmd.DebugServer(c.WFE.DebugAddr)

		wfe, err := wfe.NewWebFrontEndImpl()
		cmd.FailOnError(err, "Unable to create WFE")
		rac, sac, closeChan := setupWFE(c, auditlogger)
		wfe.RA = &rac
		wfe.SA = &sac
		wfe.Stats = stats
		wfe.SubscriberAgreementURL = c.SubscriberAgreementURL

		wfe.CertCacheDuration, err = time.ParseDuration(c.WFE.CertCacheDuration)
		cmd.FailOnError(err, "Couldn't parse certificate caching duration")
		wfe.CertNoCacheExpirationWindow, err = time.ParseDuration(c.WFE.CertNoCacheExpirationWindow)
		cmd.FailOnError(err, "Couldn't parse certificate expiration no-cache window")
		wfe.IndexCacheDuration, err = time.ParseDuration(c.WFE.IndexCacheDuration)
		cmd.FailOnError(err, "Couldn't parse index caching duration")
		wfe.IssuerCacheDuration, err = time.ParseDuration(c.WFE.IssuerCacheDuration)
		cmd.FailOnError(err, "Couldn't parse issuer caching duration")

		wfe.IssuerCert, err = cmd.LoadCert(c.Common.IssuerCert)
		cmd.FailOnError(err, fmt.Sprintf("Couldn't read issuer cert [%s]", c.Common.IssuerCert))

		go cmd.ProfileCmd("WFE", stats)

		go func() {
			// sit around and reconnect to AMQP if the channel
			// drops for some reason and repopulate the wfe object
			// with new RA and SA rpc clients.
			for {
				for err := range closeChan {
					auditlogger.Warning(fmt.Sprintf(" [!] AMQP Channel closed, will reconnect in 5 seconds: [%s]", err))
					time.Sleep(time.Second * 5)
					rac, sac, closeChan = setupWFE(c, auditlogger)
					wfe.RA = &rac
					wfe.SA = &sac
				}
			}
		}()

		// Set up paths
		wfe.BaseURL = c.Common.BaseURL
		h, err := wfe.Handler()
		cmd.FailOnError(err, "Problem setting up HTTP handlers")

		auditlogger.Info(app.VersionString())

		// Add HandlerTimer to output resp time + success/failure stats to statsd

		auditlogger.Info(fmt.Sprintf("Server running, listening on %s...\n", c.WFE.ListenAddress))
		err = http.ListenAndServe(c.WFE.ListenAddress, HandlerTimer(h, stats))
		cmd.FailOnError(err, "Error starting HTTP server")
	}

	app.Run()
}
