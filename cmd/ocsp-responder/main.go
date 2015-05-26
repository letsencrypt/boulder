// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	cfocsp "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/ocsp"
	"golang.org/x/crypto/ocsp"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
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

/*

We assume that OCSP responses are stored in a very simple database table,
with two columns: serialNumber and response

  CREATE TABLE ocsp_responses (serialNumber TEXT, response BLOB);

The serialNumber field may have any type to which Go will match a string,
so you can be more efficient than TEXT if you like.  We use it to store the
serial number in base64.  You probably want to have an index on the
serialNumber field, since we will always query on it.

*/
type DBSource struct {
	db        *sql.DB
	caKeyHash []byte
}

func NewSourceFromDatabase(db *sql.DB, caKeyHash []byte) (src *DBSource, err error) {
	src = &DBSource{db: db, caKeyHash: caKeyHash}
	return
}

const responseQuery = "SELECT resposne FROM ocsp_responses WHERE serialNumber"

func (src *DBSource) Response(req *ocsp.Request) (response []byte, present bool) {
	// Check that this request is for the proper CA
	if bytes.Compare(req.IssuerKeyHash, src.caKeyHash) != 0 {
		present = false
		return
	}

	// SELECT resposne FROM ocsp_responses WHERE serialNumber
	err := src.db.QueryRow(responseQuery).Scan(&response)
	if err != nil {
		present = false
		return
	}

	present = true
	return
}

func main() {
	app := cmd.NewAppShell("boulder-ocsp")
	app.Action = func(c cmd.Config) {
		// Set up logging
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
		cmd.FailOnError(err, "Could not connect to Syslog")

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		blog.SetAuditLogger(auditlogger)

		go cmd.ProfileCmd("OCSP", stats)

		// Connect to the DB
		db, err := sql.Open(c.OCSP.DBDriver, c.OCSP.DBName)
		cmd.FailOnError(err, "Could not connect to database")
		defer db.Close()

		// Load the CA's key and hash it
		caCertDER, err := cmd.LoadCert(c.CA.IssuerCert)
		cmd.FailOnError(err, fmt.Sprintf("Couldn't read issuer cert [%s]", c.CA.IssuerCert))
		caCert, err := x509.ParseCertificate(caCertDER)
		cmd.FailOnError(err, fmt.Sprintf("Couldn't parse cert read from [%s]", c.CA.IssuerCert))
		h := sha1.New()
		h.Write(caCert.RawSubjectPublicKeyInfo)
		caKeyHash := h.Sum(nil)

		// Construct source from DB
		src, err := NewSourceFromDatabase(db, caKeyHash)
		cmd.FailOnError(err, "Could not connect to OCSP database")

		// Configure HTTP
		http.Handle(c.OCSP.Path, cfocsp.Responder{Source: src})

		// Add HandlerTimer to output resp time + success/failure stats to statsd
		err = http.ListenAndServe(c.WFE.ListenAddress, HandlerTimer(http.DefaultServeMux, stats))
		cmd.FailOnError(err, "Error starting HTTP server")
	}

	app.Run()
}
