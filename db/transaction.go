package db

import (
	"context"

	"github.com/go-gorp/gorp/v3"
)

// txFunc represents a function that does work in the context of a transaction.
type txFunc func(txWithCtx gorp.SqlExecutor) (interface{}, error)

// WithTransaction runs the given function in a transaction, rolling back if it
// returns an error and committing if not. The provided context is also attached
// to the transaction. WithTransaction also passes through a value returned by
// `f`, if there is no error.
func WithTransaction(ctx context.Context, dbMap *WrappedMap, f txFunc) (interface{}, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// We want to make sure `BeginTx(ctx)` is called on the underlying `*sql.DB`, because that
	// is the variant that is documented to rollback the transaction on context cancel.
	// Gorp does that when you apply WithContext to the dbMap and then call `Begin()`.
	// https://github.com/go-gorp/gorp/blob/v2.2.0/gorp.go#L667-L669
	se := dbMap.WithContext(ctx).(WrappedExecutor).SqlExecutor.(*gorp.DbMap)
	tx, err := se.Begin()
	if err != nil {
		return nil, err
	}
	result, err := f(tx)
	if err != nil {
		return nil, err
	}
	err = tx.Commit()
	if err != nil {
		return nil, err
	}
	return result, nil
}
