package sa

import (
	"golang.org/x/net/context"
	"gopkg.in/go-gorp/gorp.v2"
)

type transaction interface {
	dbOneSelector
	dbInserter
	dbSelectExecer
	Delete(...interface{}) (int64, error)
	Get(interface{}, ...interface{}) (interface{}, error)
	Update(...interface{}) (int64, error)
}

type txFunc func(transaction) error

// withTransaction runs the given function in a transaction, rolling back if it
// returns an error and committing if not. The provided context is also attached
// to the transaction. Because `f` only accepts a transaction as an argument, it
// is expected that it will be a closure, with additional inputs and outputs
// coming from the outer function.
func withTransaction(ctx context.Context, dbMap *gorp.DbMap, f txFunc) error {
	tx, err := dbMap.Begin()
	if err != nil {
		return err
	}
	txWithCtx := tx.WithContext(ctx)
	err = f(txWithCtx)
	if err != nil {
		return Rollback(tx, err)
	}
	return tx.Commit()
}
