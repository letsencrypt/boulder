// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	cfocsp "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/ocsp"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/golang.org/x/crypto/ocsp"
	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
)

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

/*
DBSource maps a given Database schema to a CA Key Hash, so we can pick
from among them when presented with OCSP requests for different certs.

We assume that OCSP responses are stored in a very simple database table,
with two columns: serialNumber and response

  CREATE TABLE ocsp_responses (serialNumber TEXT, response BLOB);

The serialNumber field may have any type to which Go will match a string,
so you can be more efficient than TEXT if you like.  We use it to store the
serial number in base64.  You probably want to have an index on the
serialNumber field, since we will always query on it.

*/
type DBSource struct {
	dbMap     *gorp.DbMap
	caKeyHash []byte
}

// NewSourceFromDatabase produces a DBSource representing the binding of a
// given DB schema to a CA key.
func NewSourceFromDatabase(dbMap *gorp.DbMap, caKeyHash []byte) (src *DBSource, err error) {
	src = &DBSource{dbMap: dbMap, caKeyHash: caKeyHash}
	return
}

// Response is called by the HTTP server to handle a new OCSP request.
func (src *DBSource) Response(req *ocsp.Request) (response []byte, present bool) {
	log := blog.GetAuditLogger()

	// Check that this request is for the proper CA
	if bytes.Compare(req.IssuerKeyHash, src.caKeyHash) != 0 {
		log.Debug(fmt.Sprintf("Request intended for CA Cert ID: %s", hex.EncodeToString(req.IssuerKeyHash)))
		present = false
		return
	}

	serialString := core.SerialToString(req.SerialNumber)
	log.Debug(fmt.Sprintf("Searching for OCSP issued by us for serial %s", serialString))

	var ocspResponse core.OCSPResponse
	err := src.dbMap.SelectOne(&ocspResponse, "SELECT * from ocspResponses WHERE serial = :serial ORDER BY createdAt DESC LIMIT 1;",
		map[string]interface{}{"serial": serialString})
	if err != nil {
		present = false
		return
	}

	log.Info(fmt.Sprintf("OCSP Response sent for CA=%s, Serial=%s", hex.EncodeToString(src.caKeyHash), serialString))

	response = ocspResponse.Response
	present = true
	return
}

func main() {
	app := cmd.NewAppShell("boulder-ocsp-responder")
	app.Action = func(c cmd.Config) {
		// Set up logging
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
		cmd.FailOnError(err, "Could not connect to Syslog")

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		blog.SetAuditLogger(auditlogger)

		go cmd.DebugServer(c.OCSPResponder.DebugAddr)

		go cmd.ProfileCmd("OCSP", stats)

		auditlogger.Info(app.VersionString())

		// Configure DB
		dbMap, err := sa.NewDbMap(c.OCSPResponder.DBConnect)
		cmd.FailOnError(err, "Could not connect to database")
		sa.SetSQLDebug(dbMap, c.SQL.SQLDebug)

		// Load the CA's key so we can store its AuthorityKeyId in the DB
		caCertDER, err := cmd.LoadCert(c.Common.IssuerCert)
		cmd.FailOnError(err, fmt.Sprintf("Couldn't read issuer cert [%s]", c.Common.IssuerCert))
		caCert, err := x509.ParseCertificate(caCertDER)
		cmd.FailOnError(err, fmt.Sprintf("Couldn't parse cert read from [%s]", c.Common.IssuerCert))

		// Construct source from DB
		auditlogger.Info(fmt.Sprintf("Loading OCSP Database for CA Cert ID: %s", hex.EncodeToString(caCert.AuthorityKeyId)))
		src, err := NewSourceFromDatabase(dbMap, caCert.AuthorityKeyId)
		cmd.FailOnError(err, "Could not connect to OCSP database")

		// Configure HTTP
		m := http.NewServeMux()
		m.Handle(c.OCSPResponder.Path, cfocsp.Responder{Source: src})

		// Add HandlerTimer to output resp time + success/failure stats to statsd
		auditlogger.Info(fmt.Sprintf("Server running, listening on %s...\n", c.OCSPResponder.ListenAddress))
		err = http.ListenAndServe(c.OCSPResponder.ListenAddress, HandlerTimer(m, stats))
		cmd.FailOnError(err, "Error starting HTTP server")
	}

	app.Run()
}
