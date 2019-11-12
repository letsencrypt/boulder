package db

import (
	"database/sql"
	"testing"

	"github.com/go-sql-driver/mysql"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
	"gopkg.in/go-gorp/gorp.v2"
)

func TestRollback(t *testing.T) {
	// NOTE(@cpu): We avoid using sa.NewDBMapFromConfig here because it would
	// create a cyclic dependency. The `sa` package depends on `db` for
	// `WithTransaction`. The `db` package can't depend on the `sa` for creating
	// a DBMap. Since we're only doing this for a simple unit test we can make our
	// own dbMap by hand (how artisanal).
	var config *mysql.Config
	config, err := mysql.ParseDSN(vars.DBConnSA)
	test.AssertNotError(t, err, "parsing DBConnSA DSN")

	dbConn, err := sql.Open("mysql", config.FormatDSN())
	test.AssertNotError(t, err, "opening DB connection")

	dialect := gorp.MySQLDialect{Engine: "InnoDB", Encoding: "UTF8"}
	// NOTE(@cpu): We avoid giving a sa.BoulderTypeConverter to the DbMap field to
	// avoid the cyclic dep. We don't need to convert any types in this test.
	dbMap := &gorp.DbMap{Db: dbConn, Dialect: dialect, TypeConverter: nil}

	tx, _ := dbMap.Begin()
	// Commit the transaction so that a subsequent Rollback will always fail.
	_ = tx.Commit()

	innerErr := berrors.NotFoundError("Gone, gone, gone")
	result := Rollback(tx, innerErr)

	// Since the tx.Rollback will fail we expect the result to be a wrapped error
	test.AssertNotEquals(t, result, innerErr)
	if rbErr, ok := result.(*RollbackError); !ok {
		t.Fatal("Result was not a RollbackError")
		test.AssertEquals(t, rbErr.Err, innerErr)
		test.AssertNotNil(t, rbErr.RollbackErr, "RollbackErr was nil")
	}

	// Create a new transaction and don't commit it this time. The rollback should
	// succeed.
	tx, _ = dbMap.Begin()
	result = Rollback(tx, innerErr)

	// We expect that the err is returned unwrapped.
	test.AssertEquals(t, result, innerErr)
}
