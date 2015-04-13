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

func setupWFE(c cmd.Config, auditlogger *blog.AuditLogger) (rpc.RegistrationAuthorityClient, rpc.StorageAuthorityClient, chan *amqp.Error) {
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

func HandlerTimer(handler http.Handler, stats statsd.Statter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cStart := time.Now()
		// FIX: this somehow goes negative sometimes?
		stats.Inc("HttpConnectionsOpen", 1, 1.0)

		handler.ServeHTTP(w, r)

		stats.Dec("HttpConnectionsOpen", 1, 1.0)
		stats.TimingDuration(fmt.Sprintf("HttpResponseTime.%s", r.URL), time.Since(cStart), 1.0)
		// incr success / failure counters
		// (FIX: this doesn't seem to really work at catching errors...)
		success := true
		for _, h := range w.Header()["Content-Type"] {
			if h == "application/problem+json" {
				success = false
				break
			}
		}
		if success {
			stats.Inc(fmt.Sprintf("Http.%s.Success", r.URL), 1, 1.0)
		} else {
			stats.Inc(fmt.Sprintf("Http.%s.Error", r.URL), 1, 1.0)
		}
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

		wfe := wfe.NewWebFrontEndImpl(auditlogger)
		rac, sac, closeChan := setupWFE(c, auditlogger)
		wfe.RA = &rac
		wfe.SA = &sac
		wfe.Stats = stats

		go cmd.ProfileCmd("WFE", stats, auditlogger)

		go func() {
			// sit around and reconnect to AMQP if the channel
			// drops for some reason and repopulate the wfe object
			// with new RA and SA rpc clients.
			for {
				for err := range closeChan {
					auditlogger.Warning(fmt.Sprintf("AMQP Channel closed, will reconnect in 5 seconds: [%s]", err))
					time.Sleep(time.Second * 5)
					rac, sac, closeChan = setupWFE(c, auditlogger)
					wfe.RA = &rac
					wfe.SA = &sac
					auditlogger.Warning("Reconnected to AMQP")
				}
			}
		}()

		// Go!
		newRegPath := "/acme/new-reg"
		regPath := "/acme/reg/"
		newAuthzPath := "/acme/new-authz"
		authzPath := "/acme/authz/"
		newCertPath := "/acme/new-cert"
		certPath := "/acme/cert/"
		wfe.NewReg = c.WFE.BaseURL + newRegPath
		wfe.RegBase = c.WFE.BaseURL + regPath
		wfe.NewAuthz = c.WFE.BaseURL + newAuthzPath
		wfe.AuthzBase = c.WFE.BaseURL + authzPath
		wfe.NewCert = c.WFE.BaseURL + newCertPath
		wfe.CertBase = c.WFE.BaseURL + certPath
		http.HandleFunc(newRegPath, wfe.NewRegistration)
		http.HandleFunc(newAuthzPath, wfe.NewAuthorization)
		http.HandleFunc(newCertPath, wfe.NewCertificate)
		http.HandleFunc(regPath, wfe.Registration)
		http.HandleFunc(authzPath, wfe.Authorization)
		http.HandleFunc(certPath, wfe.Certificate)

		// Add a simple ToS
		termsPath := "/terms"
		http.HandleFunc(termsPath, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "You agree to do the right thing")
		})
		wfe.SubscriberAgreementURL = c.WFE.BaseURL + termsPath

		// Add HandlerTimer to output resp time + success/failure stats to statsd
		err = http.ListenAndServe(c.WFE.ListenAddress, HandlerTimer(http.DefaultServeMux, stats))
		cmd.FailOnError(err, "Error starting HTTP server")
	}

	app.Run()
}
