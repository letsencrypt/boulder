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

	// We do this in a transaction to make sure that the foreign
	// key checks remain disabled even if the db object chooses
	// another connection to make the deletion on. Note that
	// `alter table` statements will silently cause transactions
	// to commit, so we do them outside of the transaction.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("unable to start transaction to delete all rows: %s", err)
	}

	_, err = tx.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 0")
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("unable to disable FOREIGN_KEY_CHECKS: %s", err)
	}

	for _, tn := range ts {
		// 1 = 1 here prevents the i_am_a_dummy setting from rejecting the
		// DELETE for not having a WHERE clause.
		_, err = tx.ExecContext(ctx, "DELETE FROM `"+tn+"` WHERE 1 = 1")
		if err != nil {
			_, _ = tx.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 1")
			_ = tx.Rollback()
			return fmt.Errorf("unable to delete all rows from table %#v: %s", tn, err)
		}
	}
	_, err = tx.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 1")
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("unable to re-enable FOREIGN_KEY_CHECKS: %s", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("unable to commit transaction to delete all rows: %s", err)
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
