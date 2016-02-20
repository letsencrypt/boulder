// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"crypto/x509"
	"database/sql"
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
	"github.com/letsencrypt/boulder/metrics"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
)

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
	dbMap     dbSelector
	caKeyHash []byte
	log       *blog.AuditLogger
}

// Since the only thing we use from gorp is the SelectOne method on the
// gorp.DbMap object, we just define the interface an interface with that method
// instead of importing all of gorp. This also allows us to simulate MySQL failures
// by mocking the interface.
type dbSelector interface {
	SelectOne(holder interface{}, query string, args ...interface{}) error
}

// NewSourceFromDatabase produces a DBSource representing the binding of a
// given DB schema to a CA key.
func NewSourceFromDatabase(dbMap dbSelector, caKeyHash []byte, log *blog.AuditLogger) (src *DBSource, err error) {
	src = &DBSource{dbMap: dbMap, caKeyHash: caKeyHash, log: log}
	return
}

// Response is called by the HTTP server to handle a new OCSP request.
func (src *DBSource) Response(req *ocsp.Request) ([]byte, bool) {
	// Check that this request is for the proper CA
	if bytes.Compare(req.IssuerKeyHash, src.caKeyHash) != 0 {
		src.log.Debug(fmt.Sprintf("Request intended for CA Cert ID: %s", hex.EncodeToString(req.IssuerKeyHash)))
		return nil, false
	}

	serialString := core.SerialToString(req.SerialNumber)
	src.log.Debug(fmt.Sprintf("Searching for OCSP issued by us for serial %s", serialString))

	var response []byte
	defer func() {
		if len(response) != 0 {
			src.log.Info(fmt.Sprintf("OCSP Response sent for CA=%s, Serial=%s", hex.EncodeToString(src.caKeyHash), serialString))
		}
	}()
	err := src.dbMap.SelectOne(
		&response,
		"SELECT ocspResponse FROM certificateStatus WHERE serial = :serial",
		map[string]interface{}{"serial": serialString},
	)
	if err != nil && err != sql.ErrNoRows {
		src.log.Err(fmt.Sprintf("Failed to retrieve response from certificateStatus table: %s", err))
	}
	if err != nil {
		return nil, false
	}

	return response, true
}

func makeDBSource(dbMap dbSelector, issuerCert string, log *blog.AuditLogger) (*DBSource, error) {
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
	return NewSourceFromDatabase(dbMap, caCert.SubjectKeyId, log)
}

func main() {
	app := cmd.NewAppShell("boulder-ocsp-responder", "Handles OCSP requests")
	app.Action = func(c cmd.Config, stats statsd.Statter, auditlogger *blog.AuditLogger) {
		go cmd.DebugServer(c.OCSPResponder.DebugAddr)

		go cmd.ProfileCmd("OCSP", stats)

		config := c.OCSPResponder
		var source cfocsp.Source

		// DBConfig takes precedence over Source, if present.
		dbConnect, err := config.DBConfig.URL()
		cmd.FailOnError(err, "Reading DB config")
		if dbConnect == "" {
			dbConnect = config.Source
		}
		url, err := url.Parse(dbConnect)
		cmd.FailOnError(err, fmt.Sprintf("Source was not a URL: %s", config.Source))

		if url.Scheme == "mysql+tcp" {
			auditlogger.Info(fmt.Sprintf("Loading OCSP Database for CA Cert: %s", c.Common.IssuerCert))
			dbMap, err := sa.NewDbMap(config.Source)
			cmd.FailOnError(err, "Could not connect to database")
			if c.SQL.SQLDebug {
				sa.SetSQLDebug(dbMap, true)
			}
			source, err = makeDBSource(dbMap, c.Common.IssuerCert, auditlogger)
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
		m := mux(stats, c.OCSPResponder.Path, source)
		srv := &http.Server{
			Addr:    c.OCSPResponder.ListenAddress,
			Handler: m,
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

func mux(stats statsd.Statter, responderPath string, source cfocsp.Source) http.Handler {
	m := http.StripPrefix(responderPath, cfocsp.NewResponder(source))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/" {
			w.Header().Set("Cache-Control", "max-age=43200") // Cache for 12 hours
			w.WriteHeader(200)
			return
		}
		m.ServeHTTP(w, r)
	})
	return metrics.NewHTTPMonitor(stats, h, "OCSP")
}
