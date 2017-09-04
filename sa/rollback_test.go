package sa

import (
	"testing"

	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/test"
)

func TestRollback(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	tx, _ := sa.dbMap.Begin()
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
	tx, _ = sa.dbMap.Begin()
	result = Rollback(tx, innerErr)

	// We expect that the err is returned unwrapped.
	test.AssertEquals(t, result, innerErr)
}
