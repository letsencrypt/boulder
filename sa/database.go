// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sa

import (
	"database/sql"
	"fmt"
	"net/url"

	// Load both drivers to allow configuring either
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/go-sql-driver/mysql"
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/mattn/go-sqlite3"

	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

var dialectMap = map[string]interface{}{
	"sqlite3":  gorp.SqliteDialect{},
	"mysql":    gorp.MySQLDialect{Engine: "InnoDB", Encoding: "UTF8"},
	"postgres": gorp.PostgresDialect{},
}

// Makes sure that the parseTime=true parm is present in the DSN
func fixMysqlDSN(dsn string) (string, error) {
	// DSN format: [user@][host]/dbname?[?param1=value1&paramN=valueN]
	var i int
	var query string
	// Find the last '/', which separates the dbname
	for i = len(dsn) - 1; i >= 0; i-- {
		if dsn[i] == '/' {
			// Find the next '?', which separates the query
			for i += 1; i < len(dsn); i++ {
				if dsn[i] == '?' {
					query = dsn[i+1:]
					break
				}
			}
			break
		}
	}
	if i > 0 {
		// Parse the query and correct value for parseTime, if necessary
		dsnParams, err := url.ParseQuery(query)
		if err != nil {
			return "", err
		}
		if k := dsnParams.Get("parseTime"); k != "true" {
			dsnParams.Set("parseTime", "true")
			return dsn[:i] + "?" + dsnParams.Encode(), nil
		}
		return dsn, nil
	}
	return "", fmt.Errorf("malformed MySQL DSN: %s", dsn)
}

// NewDbMap creates the root gorp mapping object. Create one of these for each
// database schema you wish to map. Each DbMap contains a list of mapped tables.
// It automatically maps the tables for the primary parts of Boulder around the
// Storage Authority. This may require some further work when we use a disjoint
// schema, like that for `certificate-authority-data.go`.
func NewDbMap(driver string, dbConnect string) (dbmap *gorp.DbMap, err error) {
	logger := blog.GetAuditLogger()

	if driver == "mysql" {
		dbConnect, err = fixMysqlDSN(dbConnect)
		if err != nil {
			return
		}
	}

	db, err := sql.Open(driver, dbConnect)
	if err != nil {
		return
	}
	if err = db.Ping(); err != nil {
		return
	}

	logger.Debug("Connecting to database")

	dialect, ok := dialectMap[driver].(gorp.Dialect)
	if !ok {
		err = fmt.Errorf("Couldn't find dialect for %s", driver)
		return
	}

	logger.Info("Connected to database")

	dbmap = &gorp.DbMap{Db: db, Dialect: dialect, TypeConverter: BoulderTypeConverter{}}

	initTables(dbmap)

	return
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
