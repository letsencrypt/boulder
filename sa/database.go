package sa

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"gopkg.in/go-gorp/gorp.v2"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
)

// NewDbMap creates the root gorp mapping object. Create one of these for each
// database schema you wish to map. Each DbMap contains a list of mapped
// tables. It automatically maps the tables for the primary parts of Boulder
// around the Storage Authority.
func NewDbMap(dbConnect string, maxOpenConns int) (*gorp.DbMap, error) {
	var err error
	var config *mysql.Config
	if strings.HasPrefix(dbConnect, "mysql+tcp://") {
		dbConnect, err = recombineCustomMySQLURL(dbConnect)
		if err != nil {
			return nil, err
		}
	}

	config, err = mysql.ParseDSN(dbConnect)
	if err != nil {
		return nil, err
	}

	return NewDbMapFromConfig(config, maxOpenConns)
}

// sqlOpen is used in the tests to check that the arguments are properly
// transformed
var sqlOpen = func(dbType, connectStr string) (*sql.DB, error) {
	return sql.Open(dbType, connectStr)
}

// setMaxOpenConns is also used so that we can replace it for testing.
var setMaxOpenConns = func(db *sql.DB, maxOpenConns int) {
	db.SetMaxOpenConns(maxOpenConns)
}

// NewDbMapFromConfig functions similarly to NewDbMap, but it takes the
// decomposed form of the connection string, a *mysql.Config.
func NewDbMapFromConfig(config *mysql.Config, maxOpenConns int) (*gorp.DbMap, error) {
	adjustMySQLConfig(config)

	db, err := sqlOpen("mysql", config.FormatDSN())
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	setMaxOpenConns(db, maxOpenConns)

	dialect := gorp.MySQLDialect{Engine: "InnoDB", Encoding: "UTF8"}
	dbmap := &gorp.DbMap{Db: db, Dialect: dialect, TypeConverter: BoulderTypeConverter{}}

	initTables(dbmap)

	return dbmap, err
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

// recombineCustomMySQLURL transforms the legacy database URLs into the
// URL-like strings expected by the mysql database driver.
//
// In the past, changes to the connection string were achieved by passing it
// into url.Parse and editing the query string that way, so the string had to
// be a valid URL. The mysql driver needs the Host data to be wrapped in
// "tcp()" but url.Parse will escape the parentheses and the mysql driver
// doesn't understand them. So, we couldn't have "tcp()" in the configs, but
// couldn't leave it out before passing it to the mysql driver.  Similarly, the
// driver needs the password and username unescaped. The compromise was to do
// the leg work if the connection string's scheme is a fake one called
// "mysql+tcp://".
//
// Upon the addition of
// https://godoc.org/github.com/go-sql-driver/mysql#Config, this was no longer
// necessary, as the changes could be made on the decomposed struct version of
// the connection url. This method converts the old format into the format
// expected by the library.
func recombineCustomMySQLURL(dbConnect string) (string, error) {
	dbConnect = strings.TrimSpace(dbConnect)
	dbURL, err := url.Parse(dbConnect)
	if err != nil {
		return "", err
	}

	if dbURL.Scheme != "mysql+tcp" {
		format := "given database connection string was not a mysql+tcp:// URL, was %#v"
		return "", fmt.Errorf(format, dbURL.Scheme)
	}

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
	return dbConn + dbURL.EscapedPath() + "?" + dbURL.RawQuery, nil
}

// SetSQLDebug enables GORP SQL-level Debugging
func SetSQLDebug(dbMap *gorp.DbMap, log blog.Logger) {
	dbMap.TraceOn("SQL: ", &SQLLogger{log})
}

// SQLLogger adapts the Boulder Logger to a format GORP can use.
type SQLLogger struct {
	blog.Logger
}

// Printf adapts the AuditLogger to GORP's interface
func (log *SQLLogger) Printf(format string, v ...interface{}) {
	log.Debug(fmt.Sprintf(format, v...))
}

func ReportDbConnCount(dbMap *gorp.DbMap, statter metrics.Scope) {
	db := dbMap.Db
	for {
		statter.Gauge("OpenConnections", int64(db.Stats().OpenConnections))
		time.Sleep(1 * time.Second)
	}
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
	pendingAuthzTable := dbMap.AddTableWithName(pendingauthzModel{}, "pendingAuthorizations").SetKeys(false, "ID")
	pendingAuthzTable.SetVersionCol("LockCol")
	dbMap.AddTableWithName(authzModel{}, "authz").SetKeys(false, "ID")
	dbMap.AddTableWithName(challModel{}, "challenges").SetKeys(true, "ID").SetVersionCol("LockCol")
	dbMap.AddTableWithName(issuedNameModel{}, "issuedNames").SetKeys(true, "ID")
	dbMap.AddTableWithName(core.Certificate{}, "certificates").SetKeys(false, "Serial")
	dbMap.AddTableWithName(core.CertificateStatus{}, "certificateStatus").SetKeys(false, "Serial")
	dbMap.AddTableWithName(core.CRL{}, "crls").SetKeys(false, "Serial")
	dbMap.AddTableWithName(core.SignedCertificateTimestamp{}, "sctReceipts").SetKeys(true, "ID").SetVersionCol("LockCol")
	dbMap.AddTableWithName(core.FQDNSet{}, "fqdnSets").SetKeys(true, "ID")
	dbMap.AddTableWithName(certStatusModel{}, "certificateStatus").SetKeys(false, "Serial")
	dbMap.AddTableWithName(orderModel{}, "orders").SetKeys(true, "ID")
	dbMap.AddTableWithName(orderToAuthzModel{}, "orderToAuthz").SetKeys(false, "OrderID", "AuthzID")
	dbMap.AddTableWithName(requestedNameModel{}, "requestedNames").SetKeys(false, "OrderID")
	dbMap.AddTableWithName(core.OrderFQDNSet{}, "orderFqdnSets").SetKeys(false, "ID")
}
