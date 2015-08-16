// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sa

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"

	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/go-sql-driver/mysql"
	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

// NewDbMap creates the root gorp mapping object. Create one of these for each
// database schema you wish to map. Each DbMap contains a list of mapped tables.
// It automatically maps the tables for the primary parts of Boulder around the
// Storage Authority. This may require some further work when we use a disjoint
// schema, like that for `certificate-authority-data.go`.
func NewDbMap(dbConnect string) (*gorp.DbMap, error) {
	logger := blog.GetAuditLogger()

	var err error
	dbConnect, err = recombineURLForDB(dbConnect)
	if err != nil {
		return nil, err
	}

	logger.Debug("Connecting to database")

	db, err := sql.Open("mysql", dbConnect)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}

	dialect := gorp.MySQLDialect{Engine: "InnoDB", Encoding: "UTF8"}
	dbmap := &gorp.DbMap{Db: db, Dialect: dialect, TypeConverter: BoulderTypeConverter{}}

	initTables(dbmap)

	logger.Debug("Connected to database")

	return dbmap, err
}

// recombineURLForDB transforms a database URL to a URL-like string
// that the mysql driver can use. The mysql driver needs the Host data
// to be wrapped in "tcp()" but url.Parse will escape the parentheses
// and the mysql driver doesn't understand them. So, we can't have
// "tcp()" in the configs, but can't leave it out before passing it to
// the mysql driver. Similarly, the driver needs the password and
// username unescaped. Compromise by doing the leg work if the config
// says the database URL's scheme is a fake one called
// "mysqltcp://". See
// https://github.com/go-sql-driver/mysql/issues/362 for why we have
// to futz around and avoid URL.String.
func recombineURLForDB(dbConnect string) (string, error) {
	dbConnect = strings.TrimSpace(dbConnect)
	dbURL, err := url.Parse(dbConnect)
	if err != nil {
		return "", err
	}

	if dbURL.Scheme != "mysql+tcp" {
		format := "given database connection string was not a mysql+tcp:// URL, was %#v"
		return "", fmt.Errorf(format, dbURL.Scheme)
	}

	dsnVals, err := url.ParseQuery(dbURL.RawQuery)
	if err != nil {
		return "", err
	}

	dsnVals.Set("parseTime", "true")

	// Required to make UPDATE return the number of rows matched,
	// instead of the number of rows changed by the UPDATE.
	dsnVals.Set("clientFoundRows", "true")

	user := dbURL.User.Username()
	passwd, hasPass := dbURL.User.Password()
	dbConn := ""
	if user != "" {
		dbConn = url.QueryEscape(user)
	}
	if hasPass {
		dbConn += ":" + passwd
	}
	dbConn += "@tcp(" + dbURL.Host + ")"
	// TODO(jmhodges): should be dbURL.EscapedPath() but Travis doesn't have 1.5
	return dbConn + dbURL.Path + "?" + dsnVals.Encode(), nil
}

// SetSQLDebug enables/disables GORP SQL-level Debugging
func SetSQLDebug(dbMap *gorp.DbMap, state bool) {
	dbMap.TraceOff()

	if state {
		// Enable logging
		dbMap.TraceOn("SQL: ", &SQLLogger{blog.GetAuditLogger()})
	}
}

// SQLLogger adapts the AuditLogger to a format GORP can use.
type SQLLogger struct {
	log *blog.AuditLogger
}

// Printf adapts the AuditLogger to GORP's interface
func (log *SQLLogger) Printf(format string, v ...interface{}) {
	log.log.Debug(fmt.Sprintf(format, v))
}

// initTables constructs the table map for the ORM. If you want to also create
// the tables, call CreateTablesIfNotExists on the DbMap.
func initTables(dbMap *gorp.DbMap) {
	regTable := dbMap.AddTableWithName(regModel{}, "registrations").SetKeys(true, "ID")
	regTable.SetVersionCol("LockCol")
	regTable.ColMap("Key").SetNotNull(true)
	regTable.ColMap("KeySHA256").SetNotNull(true).SetUnique(true)
	pendingAuthzTable := dbMap.AddTableWithName(pendingauthzModel{}, "pending_authz").SetKeys(false, "ID")
	pendingAuthzTable.SetVersionCol("LockCol")
	pendingAuthzTable.ColMap("Challenges").SetMaxSize(1536)

	authzTable := dbMap.AddTableWithName(authzModel{}, "authz").SetKeys(false, "ID")
	authzTable.ColMap("Challenges").SetMaxSize(1536)

	dbMap.AddTableWithName(core.Certificate{}, "certificates").SetKeys(false, "Serial")
	dbMap.AddTableWithName(core.CertificateStatus{}, "certificateStatus").SetKeys(false, "Serial").SetVersionCol("LockCol")
	dbMap.AddTableWithName(core.OCSPResponse{}, "ocspResponses").SetKeys(true, "ID")
	dbMap.AddTableWithName(core.CRL{}, "crls").SetKeys(false, "Serial")
	dbMap.AddTableWithName(core.DeniedCSR{}, "deniedCSRs").SetKeys(true, "ID")
}
