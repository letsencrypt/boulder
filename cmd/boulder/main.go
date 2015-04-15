// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	// Load both drivers to allow configuring either
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/go-sql-driver/mysql"
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/mattn/go-sqlite3"
	"github.com/letsencrypt/boulder/ca"
	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/ra"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/va"
	"github.com/letsencrypt/boulder/wfe"
)

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
	app := cmd.NewAppShell("boulder")
	app.Action = func(c cmd.Config) {
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		// Set up logging
		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
		cmd.FailOnError(err, "Could not connect to Syslog")

		// Run StatsD profiling
		go cmd.ProfileCmd("Monolith", stats)

		// Create the components
		wfe := wfe.NewWebFrontEndImpl(auditlogger)
		sa, err := sa.NewSQLStorageAuthority(auditlogger, c.SA.DBDriver, c.SA.DBName)
		cmd.FailOnError(err, "Unable to create SA")
		err = sa.InitTables()
		cmd.FailOnError(err, "Unable to initialize SA")
		ra := ra.NewRegistrationAuthorityImpl(auditlogger)
		va := va.NewValidationAuthorityImpl(auditlogger, c.CA.TestMode)

		cadb, err := ca.NewCertificateAuthorityDatabaseImpl(auditlogger, c.CA.DBDriver, c.CA.DBName)
		cmd.FailOnError(err, "Failed to create CA database")

		ca, err := ca.NewCertificateAuthorityImpl(auditlogger, c.CA.Server, c.CA.AuthKey, c.CA.Profile, c.CA.SerialPrefix, cadb)
		cmd.FailOnError(err, "Unable to create CA")

		// Wire them up
		wfe.RA = &ra
		wfe.SA = sa
		wfe.Stats = stats
		ra.CA = ca
		ra.SA = sa
		ra.VA = &va
		va.RA = &ra
		ca.SA = sa

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

		// We need to tell the RA how to make challenge URIs
		// XXX: Better way to do this?  Part of improved configuration
		ra.AuthzBase = wfe.AuthzBase

		fmt.Fprintf(os.Stderr, "Server running, listening on %s...\n", c.WFE.ListenAddress)
		err = http.ListenAndServe(c.WFE.ListenAddress, HandlerTimer(http.DefaultServeMux, stats))
		cmd.FailOnError(err, "Error starting HTTP server")
	}

	app.Run()
}
