package test

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"testing"

	"github.com/letsencrypt/boulder/test/vars"
)

var _ CleanUpDB = &sql.DB{}

// CleanUpDB is an interface with only what is needed to delete all
// rows in all tables in a database plus close the database
// connection. It is satisfied by *sql.DB.
type CleanUpDB interface {
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	io.Closer
}

// ResetBoulderTestDatabase returns a cleanup function which deletes all rows in
// all tables of the 'boulder_sa' database. Omits the 'gorp_migrations'
// table as this is used by sql-migrate (https://github.com/rubenv/sql-migrate)
// to track migrations. If it encounters an error it fails the tests.
func ResetBoulderTestDatabase(t testing.TB) func() {
	return resetTestDatabase(t, context.Background(), vars.DBConnSAFullPerms)
}

// ResetIncidentsTestDatabase returns a cleanup function which deletes all rows
// in all tables of the 'incidents_sa' database. Omits the
// 'gorp_migrations' table as this is used by sql-migrate
// (https://github.com/rubenv/sql-migrate) to track migrations. If it encounters
// an error it fails the tests.
func ResetIncidentsTestDatabase(t testing.TB) func() {
	return resetTestDatabase(t, context.Background(), vars.DBConnIncidentsFullPerms)
}

func resetTestDatabase(t testing.TB, ctx context.Context, dsn string) func() {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("Couldn't create db: %s", err)
	}
	err = deleteEverythingInAllTables(ctx, db)
	if err != nil {
		t.Fatalf("Failed to delete everything: %s", err)
	}
	return func() {
		err := deleteEverythingInAllTables(ctx, db)
		if err != nil {
			t.Fatalf("Failed to truncate tables after the test: %s", err)
		}
		_ = db.Close()
	}
}

// clearEverythingInAllTables deletes all rows in the tables available to the
// CleanUpDB passed. See allTableNamesInDB for what is meant by "all tables
// available". To be used only in test code.
func deleteEverythingInAllTables(ctx context.Context, db CleanUpDB) error {
	ts, err := allTableNamesInDB(ctx, db)
	if err != nil {
		return err
	}

	for _, tn := range ts {
		for {
			result, err := db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s LIMIT 10000", tn))
			if err != nil {
				return fmt.Errorf("unable to delete from table %q: %s", tn, err)
			}
			n, err := result.RowsAffected()
			if err != nil {
				return fmt.Errorf("deleting %q: %s", tn, err)
			}
			if n < 10000 {
				break
			}
		}
	}

	return nil
}

// allTableNamesInDB returns the names of the tables available to the passed
// CleanUpDB. Omits the 'gorp_migrations' table as this is used by sql-migrate
// (https://github.com/rubenv/sql-migrate) to track migrations.
func allTableNamesInDB(ctx context.Context, db CleanUpDB) ([]string, error) {
	r, err := db.QueryContext(ctx, "select table_name from information_schema.tables t where t.table_schema = DATABASE() and t.table_name != 'gorp_migrations';")
	if err != nil {
		return nil, err
	}
	defer r.Close()
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
