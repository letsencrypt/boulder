package test

import (
	"database/sql"
	"fmt"
	"io"
	"testing"
)

var (
	_ CleanUpDB = &sql.DB{}
)

// CleanUpDB is an interface with only what is needed to delete all
// rows in all tables in a database plus close the database
// connection. It is satisfied by *sql.DB.
type CleanUpDB interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)

	io.Closer
}

// ResetSATestDatabase deletes all rows in all tables in the SA DB.
// If fails the tests if that errors and returns a clean up function
// that will delete all rows again and close the database.
// "Tables available" means all tables that can be seen in the MariaDB
// configuration by the database user except for ones that are
// configuration only like goose_db_version (for migrations) or
// the ones describing the internal configuration of the server. To be
// used only in test code.
func ResetSATestDatabase(t *testing.T) func() {
	return resetTestDatabase(t, "sa")
}

// ResetPolicyTestDatabase deletes all rows in all tables in the Policy DB. It
// acts the same as ResetSATestDatabase.
func ResetPolicyTestDatabase(t *testing.T) func() {
	return resetTestDatabase(t, "policy")
}

func resetTestDatabase(t *testing.T, dbType string) func() {
	db, err := sql.Open("mysql", fmt.Sprintf("test_setup@tcp(localhost:3306)/boulder_%s_test", dbType))
	if err != nil {
		t.Fatalf("Couldn't create db: %s", err)
	}
	fmt.Printf("db %#v\n", db)
	if err := deleteEverythingInAllTables(db); err != nil {
		t.Fatalf("Failed to delete everything: %s", err)
	}
	return func() {
		if err := deleteEverythingInAllTables(db); err != nil {
			t.Fatalf("Failed to truncate tables after the test: %s", err)
		}
		db.Close()
	}
}

// clearEverythingInAllTables deletes all rows in the tables
// available to the CleanUpDB passed in and resets the autoincrement
// counters. See allTableNamesInDB for what is meant by "all tables
// available". To be used only in test code.
func deleteEverythingInAllTables(db CleanUpDB) error {
	ts, err := allTableNamesInDB(db)
	if err != nil {
		return err
	}
	for _, tn := range ts {
		// 1 = 1 here prevents the MariaDB i_am_a_dummy setting from
		// rejecting the DELETE for not having a WHERE clause.
		_, err := db.Exec("delete from `" + tn + "` where 1 = 1")
		if err != nil {
			return fmt.Errorf("unable to delete all rows from table %#v: %s", tn, err)
		}
		_, err = db.Exec("alter table `" + tn + "` AUTO_INCREMENT = 1")
		if err != nil {
			return fmt.Errorf("unable to reset autoincrement on table %#v: %s", tn, err)
		}
	}
	return err
}

// allTableNamesInDB returns the names of the tables available to the
// CleanUpDB passed in. "Tables available" means all tables that can
// be seen in the MariaDB configuration by the database user except
// for ones that are configuration only like goose_db_version (for
// migrations) or the ones describing the internal configuration of
// the server. To be used only in test code.
func allTableNamesInDB(db CleanUpDB) ([]string, error) {
	r, err := db.Query("select table_name from information_schema.tables t where t.table_schema = DATABASE() and t.table_name != 'goose_db_version';")
	if err != nil {
		return nil, err
	}
	var ts []string
	for r.Next() {
		tableName := ""
		err = r.Scan(&tableName)
		if err != nil {
			return nil, err
		}
		ts = append(ts, tableName)
	}
	return ts, r.Err()
}
