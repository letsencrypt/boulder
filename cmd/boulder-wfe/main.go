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
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/facebookgo/httpdown"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/wfe"
)

func setupWFE(c cmd.Config, logger *blog.AuditLogger, stats statsd.Statter) (rpc.RegistrationAuthorityClient, rpc.StorageAuthorityClient) {
	raRPC, err := rpc.NewAmqpRPCClient("WFE->RA", c.AMQP.RA.Server, c, stats)
	cmd.FailOnError(err, "Unable to create RPC client")

	saRPC, err := rpc.NewAmqpRPCClient("WFE->SA", c.AMQP.SA.Server, c, stats)
	cmd.FailOnError(err, "Unable to create RPC client")

	rac, err := rpc.NewRegistrationAuthorityClient(raRPC)
	cmd.FailOnError(err, "Unable to create RA client")

	sac, err := rpc.NewStorageAuthorityClient(saRPC)
	cmd.FailOnError(err, "Unable to create SA client")

	return rac, sac
}

func main() {
	app := cmd.NewAppShell("boulder-wfe", "Handles HTTP API requests")
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
		auditlogger.Info(app.VersionString())

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		blog.SetAuditLogger(auditlogger)

		go cmd.DebugServer(c.WFE.DebugAddr)

		wfe, err := wfe.NewWebFrontEndImpl(stats, clock.Default())
		cmd.FailOnError(err, "Unable to create WFE")
		rac, sac := setupWFE(c, auditlogger, stats)
		wfe.RA = &rac
		wfe.SA = &sac
		wfe.SubscriberAgreementURL = c.SubscriberAgreementURL

		wfe.AllowOrigins = c.WFE.AllowOrigins

		wfe.CertCacheDuration, err = time.ParseDuration(c.WFE.CertCacheDuration)
		cmd.FailOnError(err, "Couldn't parse certificate caching duration")
		wfe.CertNoCacheExpirationWindow, err = time.ParseDuration(c.WFE.CertNoCacheExpirationWindow)
		cmd.FailOnError(err, "Couldn't parse certificate expiration no-cache window")
		wfe.IndexCacheDuration, err = time.ParseDuration(c.WFE.IndexCacheDuration)
		cmd.FailOnError(err, "Couldn't parse index caching duration")
		wfe.IssuerCacheDuration, err = time.ParseDuration(c.WFE.IssuerCacheDuration)
		cmd.FailOnError(err, "Couldn't parse issuer caching duration")

		wfe.ShutdownStopTimeout, err = time.ParseDuration(c.WFE.ShutdownStopTimeout)
		cmd.FailOnError(err, "Couldn't parse shutdown stop timeout")
		wfe.ShutdownKillTimeout, err = time.ParseDuration(c.WFE.ShutdownKillTimeout)
		cmd.FailOnError(err, "Couldn't parse shutdown kill timeout")

		wfe.IssuerCert, err = cmd.LoadCert(c.Common.IssuerCert)
		cmd.FailOnError(err, fmt.Sprintf("Couldn't read issuer cert [%s]", c.Common.IssuerCert))

		go cmd.ProfileCmd("WFE", stats)

		// Set up paths
		wfe.BaseURL = c.Common.BaseURL
		h, err := wfe.Handler()
		cmd.FailOnError(err, "Problem setting up HTTP handlers")

		httpMonitor := metrics.NewHTTPMonitor(stats, h, "WFE")

		auditlogger.Info(fmt.Sprintf("Server running, listening on %s...\n", c.WFE.ListenAddress))
		srv := &http.Server{
			Addr:    c.WFE.ListenAddress,
			Handler: httpMonitor.Handle(),
		}

		hd := &httpdown.HTTP{
			StopTimeout: wfe.ShutdownStopTimeout,
			KillTimeout: wfe.ShutdownKillTimeout,
			Stats:       metrics.NewFBAdapter(stats, "WFE", clock.Default()),
		}
		err = httpdown.ListenAndServe(srv, hd)
		cmd.FailOnError(err, "Error starting HTTP server")
	}

	app.Run()
}
