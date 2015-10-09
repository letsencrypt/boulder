// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	cfocsp "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/ocsp"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/facebookgo/httpdown"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/golang.org/x/crypto/ocsp"
	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
	"github.com/letsencrypt/boulder/metrics"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
)

type cacheCtrlHandler struct {
	http.Handler
	MaxAge time.Duration
}

func (c *cacheCtrlHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", c.MaxAge/time.Second))
	c.Handler.ServeHTTP(w, r)
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
func (src *DBSource) Response(req *ocsp.Request) ([]byte, bool) {
	log := blog.GetAuditLogger()

	// Check that this request is for the proper CA
	if bytes.Compare(req.IssuerKeyHash, src.caKeyHash) != 0 {
		log.Debug(fmt.Sprintf("Request intended for CA Cert ID: %s", hex.EncodeToString(req.IssuerKeyHash)))
		return nil, false
	}

	serialString := core.SerialToString(req.SerialNumber)
	log.Debug(fmt.Sprintf("Searching for OCSP issued by us for serial %s", serialString))

	var ocspResponse core.OCSPResponse
	// Note: we order by id rather than createdAt, because otherwise we sometimes
	// get the wrong result if a certificate is revoked in the same second as its
	// last update (e.g. client issues and instant revokes).
	err := src.dbMap.SelectOne(&ocspResponse, "SELECT * from ocspResponses WHERE serial = :serial ORDER BY id DESC LIMIT 1;",
		map[string]interface{}{"serial": serialString})
	if err != nil {
		return nil, false
	}

	log.Info(fmt.Sprintf("OCSP Response sent for CA=%s, Serial=%s", hex.EncodeToString(src.caKeyHash), serialString))

	return ocspResponse.Response, true
}

func makeDBSource(dbConnect, issuerCert string, sqlDebug bool) (*DBSource, error) {
	// Configure DB
	dbMap, err := sa.NewDbMap(dbConnect)
	if err != nil {
		return nil, fmt.Errorf("Could not connect to database: %s", err)
	}
	sa.SetSQLDebug(dbMap, sqlDebug)

	// Load the CA's key so we can store its SubjectKey in the DB
	caCertDER, err := cmd.LoadCert(issuerCert)
	if err != nil {
		return nil, fmt.Errorf("Could not read issuer cert %s: %s", issuerCert, err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("Could not parse issuer cert %s: %s", issuerCert, err)
	}
	if len(caCert.SubjectKeyId) == 0 {
		return nil, fmt.Errorf("Empty subjectKeyID")
	}

	// Construct source from DB
	return NewSourceFromDatabase(dbMap, caCert.SubjectKeyId)
}

func main() {
	app := cmd.NewAppShell("boulder-ocsp-responder", "Handles OCSP requests")
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

		go cmd.DebugServer(c.OCSPResponder.DebugAddr)

		go cmd.ProfileCmd("OCSP", stats)

		config := c.OCSPResponder
		var source cfocsp.Source
		url, err := url.Parse(config.Source)
		cmd.FailOnError(err, fmt.Sprintf("Source was not a URL: %s", config.Source))

		if url.Scheme == "mysql+tcp" {
			auditlogger.Info(fmt.Sprintf("Loading OCSP Database for CA Cert: %s", c.Common.IssuerCert))
			source, err = makeDBSource(config.Source, c.Common.IssuerCert, c.SQL.SQLDebug)
			cmd.FailOnError(err, "Couldn't load OCSP DB")
		} else if url.Scheme == "file" {
			filename := url.Path
			// Go interprets cwd-relative file urls (file:test/foo.txt) as having the
			// relative part of the path in the 'Opaque' field.
			if filename == "" {
				filename = url.Opaque
			}
			source, err = cfocsp.NewSourceFromFile(filename)
			cmd.FailOnError(err, fmt.Sprintf("Couldn't read file: %s", url.Path))
		} else {
			cmd.FailOnError(errors.New(`"source" parameter not found in JSON config`), "unable to start ocsp-responder")
		}

		stopTimeout, err := time.ParseDuration(c.OCSPResponder.ShutdownStopTimeout)
		cmd.FailOnError(err, "Couldn't parse shutdown stop timeout")
		killTimeout, err := time.ParseDuration(c.OCSPResponder.ShutdownKillTimeout)
		cmd.FailOnError(err, "Couldn't parse shutdown kill timeout")

		m := http.StripPrefix(c.OCSPResponder.Path,
			handler(source, c.OCSPResponder.MaxAge.Duration))

		httpMonitor := metrics.NewHTTPMonitor(stats, m, "OCSP")
		srv := &http.Server{
			Addr:    c.OCSPResponder.ListenAddress,
			Handler: httpMonitor.Handle(),
		}

		hd := &httpdown.HTTP{
			StopTimeout: stopTimeout,
			KillTimeout: killTimeout,
			Stats:       metrics.NewFBAdapter(stats, "OCSP", clock.Default()),
		}
		err = httpdown.ListenAndServe(srv, hd)
		cmd.FailOnError(err, "Error starting HTTP server")
	}

	app.Run()
}

func handler(src cfocsp.Source, maxAge time.Duration) http.Handler {
	return &cacheCtrlHandler{
		Handler: cfocsp.Responder{Source: src},
		MaxAge:  maxAge,
	}
}
