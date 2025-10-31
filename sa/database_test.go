package sa

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

var dbHost = os.Getenv("MYSQL_ADDR")

func TestInvalidDSN(t *testing.T) {
	_, err := DBMapForTest("invalid")
	test.AssertError(t, err, "DB connect string missing the slash separating the database name")

	DSN := fmt.Sprintf("policy:password@tcp(%s)/boulder_policy_integration?readTimeout=800ms&writeTimeout=800ms&stringVarThatDoesntExist=%%27whoopsidaisies", dbHost)
	_, err = DBMapForTest(DSN)
	test.AssertError(t, err, "Variable does not exist in curated system var list, but didn't return an error and should have")

	DSN = fmt.Sprintf("policy:password@tcp(%s)/boulder_policy_integration?readTimeout=800ms&writeTimeout=800ms&concurrent_insert=2", dbHost)
	_, err = DBMapForTest(DSN)
	test.AssertError(t, err, "Variable is unable to be set in the SESSION scope, but was declared")

	DSN = fmt.Sprintf("policy:password@tcp(%s)/boulder_policy_integration?readTimeout=800ms&writeTimeout=800ms&optimizer_switch=incorrect-quoted-string", dbHost)
	_, err = DBMapForTest(DSN)
	test.AssertError(t, err, "Variable declared with incorrect quoting")

	DSN = fmt.Sprintf("policy:password@tcp(%s)/boulder_policy_integration?readTimeout=800ms&writeTimeout=800ms&concurrent_insert=%%272%%27", dbHost)
	_, err = DBMapForTest(DSN)
	test.AssertError(t, err, "Integer enum declared, but should not have been quoted")
}

var errExpected = errors.New("expected")

func TestDbSettings(t *testing.T) {
	// TODO(#5248): Add a full db.mockWrappedMap to sa/database tests
	oldSetMaxOpenConns := setMaxOpenConns
	oldSetMaxIdleConns := setMaxIdleConns
	oldSetConnMaxLifetime := setConnMaxLifetime
	oldSetConnMaxIdleTime := setConnMaxIdleTime
	defer func() {
		setMaxOpenConns = oldSetMaxOpenConns
		setMaxIdleConns = oldSetMaxIdleConns
		setConnMaxLifetime = oldSetConnMaxLifetime
		setConnMaxIdleTime = oldSetConnMaxIdleTime
	}()

	maxOpenConns := -1
	maxIdleConns := -1
	connMaxLifetime := time.Second * 1
	connMaxIdleTime := time.Second * 1

	setMaxOpenConns = func(db *sql.DB, m int) {
		maxOpenConns = m
		oldSetMaxOpenConns(db, maxOpenConns)
	}
	setMaxIdleConns = func(db *sql.DB, m int) {
		maxIdleConns = m
		oldSetMaxIdleConns(db, maxIdleConns)
	}
	setConnMaxLifetime = func(db *sql.DB, c time.Duration) {
		connMaxLifetime = c
		oldSetConnMaxLifetime(db, connMaxLifetime)
	}
	setConnMaxIdleTime = func(db *sql.DB, c time.Duration) {
		connMaxIdleTime = c
		oldSetConnMaxIdleTime(db, connMaxIdleTime)
	}
	dsnFile := path.Join(t.TempDir(), "dbconnect")
	err := os.WriteFile(dsnFile,
		[]byte(fmt.Sprintf("sa@tcp(%s)/boulder_sa_integration", dbHost)),
		os.ModeAppend)
	test.AssertNotError(t, err, "writing dbconnect file")

	config := cmd.DBConfig{
		DBConnectFile:   dsnFile,
		MaxOpenConns:    100,
		MaxIdleConns:    100,
		ConnMaxLifetime: config.Duration{Duration: 100 * time.Second},
		ConnMaxIdleTime: config.Duration{Duration: 100 * time.Second},
	}
	_, err = InitWrappedDb(config, nil, nil)
	if err != nil {
		t.Errorf("connecting to DB: %s", err)
	}
	if maxOpenConns != 100 {
		t.Errorf("maxOpenConns was not set: expected 100, got %d", maxOpenConns)
	}
	if maxIdleConns != 100 {
		t.Errorf("maxIdleConns was not set: expected 100, got %d", maxIdleConns)
	}
	if connMaxLifetime != 100*time.Second {
		t.Errorf("connMaxLifetime was not set: expected 100s, got %s", connMaxLifetime)
	}
	if connMaxIdleTime != 100*time.Second {
		t.Errorf("connMaxIdleTime was not set: expected 100s, got %s", connMaxIdleTime)
	}
}

// TODO: Change this to test `newDbMapFromMySQLConfig` instead?
func TestNewDbMap(t *testing.T) {
	mysqlConnectURL := fmt.Sprintf("policy:password@tcp(%s)/boulder_policy_integration?readTimeout=800ms&writeTimeout=800ms", dbHost)
	expected := fmt.Sprintf("policy:password@tcp(%s)/boulder_policy_integration?clientFoundRows=true&parseTime=true&readTimeout=800ms&writeTimeout=800ms&sql_mode=%%27STRICT_ALL_TABLES%%27", dbHost)
	oldSQLOpen := sqlOpen
	defer func() {
		sqlOpen = oldSQLOpen
	}()
	sqlOpen = func(dbType, connectString string) (*sql.DB, error) {
		if connectString != expected {
			t.Errorf("incorrect connection string mangling, want %#v, got %#v", expected, connectString)
		}
		return nil, errExpected
	}

	dbMap, err := DBMapForTest(mysqlConnectURL)
	if err != errExpected {
		t.Errorf("got incorrect error. Got %v, expected %v", err, errExpected)
	}
	if dbMap != nil {
		t.Errorf("expected nil, got %v", dbMap)
	}

}

func TestStrictness(t *testing.T) {
	dbMap, err := DBMapForTest(vars.DBConnSA)
	if err != nil {
		t.Fatal(err)
	}
	_, err = dbMap.ExecContext(ctx, `insert into orderToAuthz2 set
		orderID=999999999999999999999999999,
		authzID=999999999999999999999999999;`)
	if err == nil {
		t.Fatal("Expected error when providing out of range value, got none.")
	}
	if !strings.Contains(err.Error(), "Out of range value for column") {
		t.Fatalf("Got wrong type of error: %s", err)
	}
}

// TestAutoIncrementSchema tests that all of the tables in the boulder_*
// databases that have auto_increment columns use BIGINT for the data type. Our
// data is too big for INT.
func TestAutoIncrementSchema(t *testing.T) {
	dbMap, err := DBMapForTest(vars.DBInfoSchemaRoot)
	test.AssertNotError(t, err, "unexpected err making NewDbMap")

	var count int64
	err = dbMap.SelectOne(
		context.Background(),
		&count,
		`SELECT COUNT(*) FROM columns WHERE
			table_schema LIKE 'boulder%' AND
			extra LIKE '%auto_increment%' AND
			data_type != "bigint"`)
	test.AssertNotError(t, err, "unexpected err querying columns")
	test.AssertEquals(t, count, int64(0))
}
