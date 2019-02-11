package sa

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

func TestInvalidDSN(t *testing.T) {
	_, err := NewDbMap("invalid", 0)
	test.AssertError(t, err, "DB connect string missing the slash separating the database name")
}

var errExpected = errors.New("expected")

func TestMaxOpenConns(t *testing.T) {
	oldSetMaxOpenConns := setMaxOpenConns
	defer func() {
		setMaxOpenConns = oldSetMaxOpenConns
	}()
	maxOpenConns := -1
	setMaxOpenConns = func(db *sql.DB, m int) {
		maxOpenConns = m
		oldSetMaxOpenConns(db, maxOpenConns)
	}
	_, err := NewDbMap("sa@tcp(boulder-mysql:3306)/boulder_sa_integration", 100)
	if err != nil {
		t.Errorf("connecting to DB: %s", err)
	}
	if maxOpenConns != 100 {
		t.Errorf("maxOpenConns was not set: expected %d, got %d", 100, maxOpenConns)
	}
}

func TestNewDbMap(t *testing.T) {
	const mysqlConnectURL = "policy:password@tcp(boulder-mysql:3306)/boulder_policy_integration?readTimeout=800ms&writeTimeout=800ms"
	const expected = "policy:password@tcp(boulder-mysql:3306)/boulder_policy_integration?clientFoundRows=true&parseTime=true&readTimeout=800ms&writeTimeout=800ms&long_query_time=0.6400000000000001&max_statement_time=0.76&sql_mode=STRICT_ALL_TABLES"
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

	dbMap, err := NewDbMap(mysqlConnectURL, 0)
	if err != errExpected {
		t.Errorf("got incorrect error. Got %v, expected %v", err, errExpected)
	}
	if dbMap != nil {
		t.Errorf("expected nil, got %v", dbMap)
	}

}

func TestStrictness(t *testing.T) {
	dbMap, err := NewDbMap(vars.DBConnSA, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = dbMap.Exec(`insert into authz set
		id="hi", identifier="foo", status="pending", combinations="combos",
		registrationID=999999999999999999999999999;`)
	if err == nil {
		t.Fatal("Expected error when providing out of range value, got none.")
	}
	if !strings.Contains(err.Error(), "Out of range value for column") {
		t.Fatalf("Got wrong type of error: %s", err)
	}
}

func TestTimeouts(t *testing.T) {
	dbMap, err := NewDbMap(vars.DBConnSA+"?readTimeout=1s", 1)
	if err != nil {
		t.Fatal("Error setting up DB:", err)
	}
	// SLEEP is defined to return 1 if it was interrupted, but we want to actually
	// get an error to simulate what would happen with a slow query. So we wrap
	// the SLEEP in a subselect.
	_, err = dbMap.Exec(`SELECT 1 FROM (SELECT SLEEP(5)) as subselect;`)
	if err == nil {
		t.Fatal("Expected error when running slow query, got none.")
	}

	// We expect to get:
	// Error 1969: Query execution was interrupted (max_statement_time exceeded)
	// https://mariadb.com/kb/en/mariadb/mariadb-error-codes/
	if !strings.Contains(err.Error(), "Error 1969") {
		t.Fatalf("Got wrong type of error: %s", err)
	}
}
