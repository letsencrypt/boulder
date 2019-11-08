package sa

import (
	"context"
	"gopkg.in/go-gorp/gorp.v2"
)

type Transaction interface {
	dbOneSelector
	dbInserter
	dbSelectExecer
	Delete(...interface{}) (int64, error)
	Get(interface{}, ...interface{}) (interface{}, error)
	Update(...interface{}) (int64, error)
}

type DatabaseMap interface {
	dbOneSelector
	dbInserter
	dbSelectExecer
	Begin() (*gorp.Transaction, error)
}

// txFunc represents a function that does work in the context of a transaction.
type txFunc func(Transaction) (interface{}, error)

// WithTransaction runs the given function in a transaction, rolling back if it
// returns an error and committing if not. The provided context is also attached
// to the transaction. WithTransaction also passes through a value returned by
// `f`, if there is no error.
func WithTransaction(ctx context.Context, dbMap DatabaseMap, f txFunc) (interface{}, error) {
	tx, err := dbMap.Begin()
	if err != nil {
		return nil, err
	}
	txWithCtx := tx.WithContext(ctx)
	result, err := f(txWithCtx)
	if err != nil {
		return nil, Rollback(tx, err)
	}
	err = tx.Commit()
	if err != nil {
		return nil, err
	}
	return result, nil
}
