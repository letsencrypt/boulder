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

	// Provide access to the MySQL driver
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
// "mysql+tcp://". See
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

	// Ensures that MySQL/MariaDB warnings are treated as errors. This
	// avoids a number of nasty edge conditions we could wander
	// into. Common things this discovers includes places where data
	// being sent had a different type than what is in the schema,
	// strings being truncated, writing null to a NOT NULL column, and
	// so on. See
	// <https://dev.mysql.com/doc/refman/5.0/en/sql-mode.html#sql-mode-strict>.
	dsnVals.Set("strict", "true")

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
	return dbConn + dbURL.EscapedPath() + "?" + dsnVals.Encode(), nil
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
	log blog.SyslogWriter
}

// Printf adapts the AuditLogger to GORP's interface
func (log *SQLLogger) Printf(format string, v ...interface{}) {
	log.log.Debug(fmt.Sprintf(format, v...))
}

// initTables constructs the table map for the ORM.
// NOTE: For tables with an auto-increment primary key (SetKeys(true, ...)),
// it is very important to declare them as a such here. It produces a side
// effect in Insert() where the inserted object has its id field set to the
// autoincremented value that resulted from the insert. See
// https://godoc.org/github.com/coopernurse/gorp#DbMap.Insert
func initTables(dbMap *gorp.DbMap) {
	regTable := dbMap.AddTableWithName(regModel{}, "registrations").SetKeys(true, "ID")
	regTable.SetVersionCol("LockCol")
	regTable.ColMap("Key").SetNotNull(true)
	regTable.ColMap("KeySHA256").SetNotNull(true).SetUnique(true)
	pendingAuthzTable := dbMap.AddTableWithName(pendingauthzModel{}, "pendingAuthorizations").SetKeys(false, "ID")
	pendingAuthzTable.SetVersionCol("LockCol")
	dbMap.AddTableWithName(authzModel{}, "authz").SetKeys(false, "ID")
	dbMap.AddTableWithName(challModel{}, "challenges").SetKeys(true, "ID").SetVersionCol("LockCol")
	dbMap.AddTableWithName(issuedNameModel{}, "issuedNames").SetKeys(true, "ID")
	dbMap.AddTableWithName(core.Certificate{}, "certificates").SetKeys(false, "Serial")
	dbMap.AddTableWithName(core.CertificateStatus{}, "certificateStatus").SetKeys(false, "Serial").SetVersionCol("LockCol")
	dbMap.AddTableWithName(core.CRL{}, "crls").SetKeys(false, "Serial")
	dbMap.AddTableWithName(core.DeniedCSR{}, "deniedCSRs").SetKeys(true, "ID")
	dbMap.AddTableWithName(sctModel{}, "sctReceipts").SetKeys(true, "ID").SetVersionCol("LockCol")
}
