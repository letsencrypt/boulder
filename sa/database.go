package sa

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/go-gorp/gorp/v3"
	"github.com/go-sql-driver/mysql"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	boulderDB "github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
)

// DbSettings contains settings for the database/sql driver. The zero
// value of each field means use the default setting from database/sql.
// ConnMaxIdleTime and ConnMaxLifetime should be set lower than their
// mariab counterparts interactive_timeout and wait_timeout.
type DbSettings struct {
	// MaxOpenConns sets the maximum number of open connections to the
	// database. If MaxIdleConns is greater than 0 and MaxOpenConns is
	// less than MaxIdleConns, then MaxIdleConns will be reduced to
	// match the new MaxOpenConns limit. If n < 0, then there is no
	// limit on the number of open connections.
	MaxOpenConns int

	// MaxIdleConns sets the maximum number of connections in the idle
	// connection pool. If MaxOpenConns is greater than 0 but less than
	// MaxIdleConns, then MaxIdleConns will be reduced to match the
	// MaxOpenConns limit. If n < 0, no idle connections are retained.
	MaxIdleConns int

	// ConnMaxLifetime sets the maximum amount of time a connection may
	// be reused. Expired connections may be closed lazily before reuse.
	// If d < 0, connections are not closed due to a connection's age.
	ConnMaxLifetime time.Duration

	// ConnMaxIdleTime sets the maximum amount of time a connection may
	// be idle. Expired connections may be closed lazily before reuse.
	// If d < 0, connections are not closed due to a connection's idle
	// time.
	ConnMaxIdleTime time.Duration
}

// NewDbSettingsFromDBConfig returns a `DbSettings` object for the provided
// `cmd.DBConfig`.
func NewDbSettingsFromDBConfig(dbconfig cmd.DBConfig) DbSettings {
	return DbSettings{
		MaxOpenConns:    dbconfig.MaxOpenConns,
		MaxIdleConns:    dbconfig.MaxIdleConns,
		ConnMaxLifetime: dbconfig.ConnMaxLifetime.Duration,
		ConnMaxIdleTime: dbconfig.ConnMaxIdleTime.Duration,
	}
}

// NewDbMap creates a wrapped root gorp mapping object. Create one of these for
// each database schema you wish to map. Each DbMap contains a list of mapped
// tables. It automatically maps the tables for the primary parts of Boulder
// around the Storage Authority.
func NewDbMap(dbConnect string, settings DbSettings) (*boulderDB.WrappedMap, error) {
	var err error
	var config *mysql.Config

	config, err = mysql.ParseDSN(dbConnect)
	if err != nil {
		return nil, err
	}

	return NewDbMapFromConfig(config, settings)
}

// sqlOpen is used in the tests to check that the arguments are properly
// transformed
var sqlOpen = func(dbType, connectStr string) (*sql.DB, error) {
	return sql.Open(dbType, connectStr)
}

// setMaxOpenConns is also used so that we can replace it for testing.
var setMaxOpenConns = func(db *sql.DB, maxOpenConns int) {
	if maxOpenConns != 0 {
		db.SetMaxOpenConns(maxOpenConns)
	}
}

// setMaxIdleConns is also used so that we can replace it for testing.
var setMaxIdleConns = func(db *sql.DB, maxIdleConns int) {
	if maxIdleConns != 0 {
		db.SetMaxIdleConns(maxIdleConns)
	}
}

// setConnMaxLifetime is also used so that we can replace it for testing.
var setConnMaxLifetime = func(db *sql.DB, connMaxLifetime time.Duration) {
	if connMaxLifetime != 0 {
		db.SetConnMaxLifetime(connMaxLifetime)
	}
}

// setConnMaxIdleTime is also used so that we can replace it for testing.
var setConnMaxIdleTime = func(db *sql.DB, connMaxIdleTime time.Duration) {
	if connMaxIdleTime != 0 {
		db.SetConnMaxIdleTime(connMaxIdleTime)
	}
}

// NewDbMapFromConfig functions similarly to NewDbMap, but it takes the
// decomposed form of the connection string, a *mysql.Config.
func NewDbMapFromConfig(config *mysql.Config, settings DbSettings) (*boulderDB.WrappedMap, error) {
	adjustMySQLConfig(config)

	db, err := sqlOpen("mysql", config.FormatDSN())
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	setMaxOpenConns(db, settings.MaxOpenConns)
	setMaxIdleConns(db, settings.MaxIdleConns)
	setConnMaxLifetime(db, settings.ConnMaxLifetime)
	setConnMaxIdleTime(db, settings.ConnMaxIdleTime)

	dialect := gorp.MySQLDialect{Engine: "InnoDB", Encoding: "UTF8"}
	dbmap := &gorp.DbMap{Db: db, Dialect: dialect, TypeConverter: BoulderTypeConverter{}}

	initTables(dbmap)

	return &boulderDB.WrappedMap{DbMap: dbmap}, nil
}

// adjustMySQLConfig sets certain flags that we want on every connection.
func adjustMySQLConfig(conf *mysql.Config) *mysql.Config {
	// Required to turn DATETIME fields into time.Time
	conf.ParseTime = true

	// Required to make UPDATE return the number of rows matched,
	// instead of the number of rows changed by the UPDATE.
	conf.ClientFoundRows = true

	// Ensures that MySQL/MariaDB warnings are treated as errors. This
	// avoids a number of nasty edge conditions we could wander into.
	// Common things this discovers includes places where data being sent
	// had a different type than what is in the schema, strings being
	// truncated, writing null to a NOT NULL column, and so on. See
	// <https://dev.mysql.com/doc/refman/5.0/en/sql-mode.html#sql-mode-strict>.
	conf.Params = make(map[string]string)
	conf.Params["sql_mode"] = "STRICT_ALL_TABLES"

	// If a read timeout is set, we set max_statement_time to 95% of that, and
	// long_query_time to 80% of that. That way we get logs of queries that are
	// close to timing out but not yet doing so, and our queries get stopped by
	// max_statement_time before timing out the read. This generates clearer
	// errors, and avoids unnecessary reconnects.
	if conf.ReadTimeout != 0 {
		// In MariaDB, max_statement_time and long_query_time are both seconds.
		// Note: in MySQL (which we don't use), max_statement_time is millis.
		readTimeout := conf.ReadTimeout.Seconds()
		conf.Params["max_statement_time"] = fmt.Sprintf("%g", readTimeout*0.95)
		conf.Params["long_query_time"] = fmt.Sprintf("%g", readTimeout*0.80)
	}

	return conf
}

// SetSQLDebug enables GORP SQL-level Debugging
func SetSQLDebug(dbMap *boulderDB.WrappedMap, log blog.Logger) {
	dbMap.TraceOn("SQL: ", &SQLLogger{log})
}

// SQLLogger adapts the Boulder Logger to a format GORP can use.
type SQLLogger struct {
	blog.Logger
}

// Printf adapts the AuditLogger to GORP's interface
func (log *SQLLogger) Printf(format string, v ...interface{}) {
	log.Debugf(format, v...)
}

// initTables constructs the table map for the ORM.
// NOTE: For tables with an auto-increment primary key (SetKeys(true, ...)),
// it is very important to declare them as a such here. It produces a side
// effect in Insert() where the inserted object has its id field set to the
// autoincremented value that resulted from the insert. See
// https://godoc.org/github.com/coopernurse/gorp#DbMap.Insert
func initTables(dbMap *gorp.DbMap) {
	var regTable *gorp.TableMap
	regTable = dbMap.AddTableWithName(regModel{}, "registrations").SetKeys(true, "ID")

	regTable.SetVersionCol("LockCol")
	regTable.ColMap("Key").SetNotNull(true)
	regTable.ColMap("KeySHA256").SetNotNull(true).SetUnique(true)
	dbMap.AddTableWithName(authzModel{}, "authz").SetKeys(false, "ID")
	dbMap.AddTableWithName(challModel{}, "challenges").SetKeys(true, "ID")
	dbMap.AddTableWithName(issuedNameModel{}, "issuedNames").SetKeys(true, "ID")
	dbMap.AddTableWithName(core.Certificate{}, "certificates").SetKeys(true, "ID")
	dbMap.AddTableWithName(core.CertificateStatus{}, "certificateStatus").SetKeys(true, "ID")
	dbMap.AddTableWithName(core.FQDNSet{}, "fqdnSets").SetKeys(true, "ID")
	dbMap.AddTableWithName(orderModel{}, "orders").SetKeys(true, "ID")
	dbMap.AddTableWithName(orderToAuthzModel{}, "orderToAuthz").SetKeys(false, "OrderID", "AuthzID")
	dbMap.AddTableWithName(requestedNameModel{}, "requestedNames").SetKeys(false, "OrderID")
	dbMap.AddTableWithName(orderFQDNSet{}, "orderFqdnSets").SetKeys(true, "ID")
	dbMap.AddTableWithName(authzModel{}, "authz2").SetKeys(true, "ID")
	dbMap.AddTableWithName(orderToAuthzModel{}, "orderToAuthz2").SetKeys(false, "OrderID", "AuthzID")
	dbMap.AddTableWithName(recordedSerialModel{}, "serials").SetKeys(true, "ID")
	dbMap.AddTableWithName(precertificateModel{}, "precertificates").SetKeys(true, "ID")
	dbMap.AddTableWithName(keyHashModel{}, "keyHashToSerial").SetKeys(true, "ID")
}
