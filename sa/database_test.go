package sa

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/features"
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
	const mysqlConnectURL = "mysql+tcp://policy:password@boulder-mysql:3306/boulder_policy_integration?readTimeout=800ms&writeTimeout=800ms"
	const expectedTransformed = "policy:password@tcp(boulder-mysql:3306)/boulder_policy_integration?clientFoundRows=true&parseTime=true&readTimeout=800ms&strict=true&writeTimeout=800ms"

	oldSQLOpen := sqlOpen
	defer func() {
		sqlOpen = oldSQLOpen
	}()
	sqlOpen = func(dbType, connectString string) (*sql.DB, error) {
		if connectString != expectedTransformed {
			t.Errorf("incorrect connection string mangling, got %v", connectString)
		}
		return nil, errExpected
	}

	dbMap, err := NewDbMap(mysqlConnectURL, 0)
	if err != errExpected {
		t.Errorf("got incorrect error: %v", err)
	}
	if dbMap != nil {
		t.Errorf("expected nil, got %v", dbMap)
	}

}

func TestStrictness(t *testing.T) {

	// Without the UsePrefixDB feature enabled the STRICT_ALL_TABLES option will
	// not be speficied, and so we expect to see an error about the registration
	// ID provided violating a foreign key constraint
	dbMap, err := NewDbMap(vars.DBConnSA, 1)
	_, err = dbMap.Exec(`insert into authz set
		id="hi", identifier="foo", status="pending", combinations="combos",
		registrationID=999999999999999999999999999;`)
	if err == nil {
		t.Fatal("Expected error when providing unsatisfied foreign key, got none.")
	}
	if !strings.Contains(err.Error(), "Cannot add or update a child row: a foreign key constraint fails") {
		t.Fatalf("Got wrong type of error: %s", err)
	}

	// With the UsePrefixDB feature enabled the STRICT_ALL_TABLES option should be
	// specified, and so we expect to see an error about the very large
	// registration ID value instead of a foreign key error.
	features.Set(map[string]bool{"UsePrefixDB": true})
	defer features.Reset()

	dbMap, err = NewDbMap(vars.DBConnSA, 1)
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
	// First test without the UsePrefixDB feature enabled. The readTimeout
	// provided will not be prefixed onto the DB connection.
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

	// Without the timeout being respected a bad connection error occurs
	if !strings.Contains(err.Error(), "driver: bad connection") {
		t.Fatalf("Got wrong type of error when not using prefix DB: %s", err)
	}

	features.Set(map[string]bool{"UsePrefixDB": true})
	defer features.Reset()

	// Now test with the UsePrefixDB feature enabled. The readTimeout
	// provided should affect the created DB connection as intended.
	dbMap, err = NewDbMap(vars.DBConnSA+"?readTimeout=1s", 1)
	if err != nil {
		t.Fatal("Error setting up DB:", err)
	}
	_, err = dbMap.Exec(`SELECT 1 FROM (SELECT SLEEP(5)) as subselect;`)
	if err == nil {
		t.Fatal("Expected error when running slow query, got none.")
	}

	// We expect to get:
	// Error 1969: Query execution was interrupted (max_statement_time exceeded)
	// https://mariadb.com/kb/en/mariadb/mariadb-error-codes/
	if !strings.Contains(err.Error(), "Error 1969") {
		t.Fatalf("Got wrong type of error using prefix DB: %s", err)
	}
}
