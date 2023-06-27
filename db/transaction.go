package db

import (
	"context"

	"github.com/go-gorp/gorp/v3"
)

// txFunc represents a function that does work in the context of a transaction.
type txFunc func(txWithCtx Executor) (interface{}, error)

// WithTransaction runs the given function in a transaction, rolling back if it
// returns an error and committing if not. The provided context is also attached
// to the transaction. WithTransaction also passes through a value returned by
// `f`, if there is no error.
func WithTransaction(ctx context.Context, dbMap DatabaseMap, f txFunc) (interface{}, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	se := dbMap.WithContext(ctx).(WrappedExecutor).SqlExecutor.(*gorp.DbMap)
	tx, err := se.Begin()
	if err != nil {
		return nil, err
	}
	txWithCtx := tx.WithContext(ctx)
	result, err := f(txWithCtx)
	if err != nil {
		return nil, err
	}
	err = tx.Commit()
	if err != nil {
		return nil, err
	}
	return result, nil
}
