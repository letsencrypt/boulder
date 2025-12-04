// Copyright 2012 James Cooper. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package borp

import (
	"context"
	"database/sql"
	"time"
)

// Transaction represents a database transaction.
// Insert/Update/Delete/Get/Exec operations will be run in the context
// of that transaction.  Transactions should be terminated with
// a call to Commit() or Rollback()
type Transaction struct {
	dbmap  *DbMap
	tx     *sql.Tx
	closed bool
}

// Insert has the same behavior as DbMap.Insert(), but runs in a transaction.
func (t *Transaction) Insert(ctx context.Context, list ...interface{}) error {
	return insert(ctx, t.dbmap, t, list...)
}

// Update had the same behavior as DbMap.Update(), but runs in a transaction.
func (t *Transaction) Update(ctx context.Context, list ...interface{}) (int64, error) {
	return update(ctx, t.dbmap, t, nil, list...)
}

// UpdateColumns had the same behavior as DbMap.UpdateColumns(), but runs in a transaction.
func (t *Transaction) UpdateColumns(ctx context.Context, filter ColumnFilter, list ...interface{}) (int64, error) {
	return update(ctx, t.dbmap, t, filter, list...)
}

// Delete has the same behavior as DbMap.Delete(), but runs in a transaction.
func (t *Transaction) Delete(ctx context.Context, list ...interface{}) (int64, error) {
	return delete(ctx, t.dbmap, t, list...)
}

// Get has the same behavior as DbMap.Get(), but runs in a transaction.
func (t *Transaction) Get(ctx context.Context, i interface{}, keys ...interface{}) (interface{}, error) {
	return get(ctx, t.dbmap, t, i, keys...)
}

// Select has the same behavior as DbMap.Select(), but runs in a transaction.
func (t *Transaction) Select(ctx context.Context, i interface{}, query string, args ...interface{}) ([]interface{}, error) {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	args, err := t.dbmap.convertArgs(args...)
	if err != nil {
		return nil, err
	}

	return hookedselect(ctx, t.dbmap, t, i, query, args...)
}

// ExecContext has the same behavior as DbMap.ExecContext(), but runs in a transaction.
func (t *Transaction) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	args, err := t.dbmap.convertArgs(args...)
	if err != nil {
		return nil, err
	}

	if t.dbmap.logger != nil {
		now := time.Now()
		defer t.dbmap.trace(now, query, args...)
	}
	return maybeExpandNamedQueryAndExec(ctx, t, query, args...)
}

// SelectInt is a convenience wrapper around the borp.SelectInt function.
func (t *Transaction) SelectInt(ctx context.Context, query string, args ...interface{}) (int64, error) {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	args, err := t.dbmap.convertArgs(args...)
	if err != nil {
		return 0, err
	}

	return SelectInt(ctx, t, query, args...)
}

// SelectNullInt is a convenience wrapper around the borp.SelectNullInt function.
func (t *Transaction) SelectNullInt(ctx context.Context, query string, args ...interface{}) (sql.NullInt64, error) {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	args, err := t.dbmap.convertArgs(args...)
	if err != nil {
		return sql.NullInt64{}, err
	}

	return SelectNullInt(ctx, t, query, args...)
}

// SelectFloat is a convenience wrapper around the borp.SelectFloat function.
func (t *Transaction) SelectFloat(ctx context.Context, query string, args ...interface{}) (float64, error) {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	args, err := t.dbmap.convertArgs(args...)
	if err != nil {
		return 0, err
	}

	return SelectFloat(ctx, t, query, args...)
}

// SelectNullFloat is a convenience wrapper around the borp.SelectNullFloat function.
func (t *Transaction) SelectNullFloat(ctx context.Context, query string, args ...interface{}) (sql.NullFloat64, error) {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	args, err := t.dbmap.convertArgs(args...)
	if err != nil {
		return sql.NullFloat64{}, err
	}

	return SelectNullFloat(ctx, t, query, args...)
}

// SelectStr is a convenience wrapper around the borp.SelectStr function.
func (t *Transaction) SelectStr(ctx context.Context, query string, args ...interface{}) (string, error) {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	args, err := t.dbmap.convertArgs(args...)
	if err != nil {
		return "", err
	}

	return SelectStr(ctx, t, query, args...)
}

// SelectNullStr is a convenience wrapper around the borp.SelectNullStr function.
func (t *Transaction) SelectNullStr(ctx context.Context, query string, args ...interface{}) (sql.NullString, error) {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	args, err := t.dbmap.convertArgs(args...)
	if err != nil {
		return sql.NullString{}, err
	}

	return SelectNullStr(ctx, t, query, args...)
}

// SelectOne is a convenience wrapper around the borp.SelectOne function.
func (t *Transaction) SelectOne(ctx context.Context, holder interface{}, query string, args ...interface{}) error {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	args, err := t.dbmap.convertArgs(args...)
	if err != nil {
		return err
	}

	return SelectOne(ctx, t.dbmap, t, holder, query, args...)
}

// Commit commits the underlying database transaction.
func (t *Transaction) Commit() error {
	if !t.closed {
		t.closed = true
		if t.dbmap.logger != nil {
			now := time.Now()
			defer t.dbmap.trace(now, "commit;")
		}
		return t.tx.Commit()
	}

	return sql.ErrTxDone
}

// Rollback rolls back the underlying database transaction.
func (t *Transaction) Rollback() error {
	if !t.closed {
		t.closed = true
		if t.dbmap.logger != nil {
			now := time.Now()
			defer t.dbmap.trace(now, "rollback;")
		}
		return t.tx.Rollback()
	}

	return sql.ErrTxDone
}

// Savepoint creates a savepoint with the given name. The name is interpolated
// directly into the SQL SAVEPOINT statement, so you must sanitize it if it is
// derived from user input.
func (t *Transaction) Savepoint(ctx context.Context, name string) error {
	query := "savepoint " + t.dbmap.Dialect.QuoteField(name)
	if t.dbmap.logger != nil {
		now := time.Now()
		defer t.dbmap.trace(now, query, nil)
	}
	_, err := t.ExecContext(ctx, query)
	return err
}

// RollbackToSavepoint rolls back to the savepoint with the given name. The
// name is interpolated directly into the SQL SAVEPOINT statement, so you must
// sanitize it if it is derived from user input.
func (t *Transaction) RollbackToSavepoint(ctx context.Context, savepoint string) error {
	query := "rollback to savepoint " + t.dbmap.Dialect.QuoteField(savepoint)
	if t.dbmap.logger != nil {
		now := time.Now()
		defer t.dbmap.trace(now, query, nil)
	}
	_, err := t.ExecContext(ctx, query)
	return err
}

// ReleaseSavepint releases the savepoint with the given name. The name is
// interpolated directly into the SQL SAVEPOINT statement, so you must sanitize
// it if it is derived from user input.
func (t *Transaction) ReleaseSavepoint(ctx context.Context, savepoint string) error {
	query := "release savepoint " + t.dbmap.Dialect.QuoteField(savepoint)
	if t.dbmap.logger != nil {
		now := time.Now()
		defer t.dbmap.trace(now, query, nil)
	}
	_, err := t.ExecContext(ctx, query)
	return err
}

// Prepare has the same behavior as DbMap.Prepare(), but runs in a transaction.
func (t *Transaction) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	if t.dbmap.logger != nil {
		now := time.Now()
		defer t.dbmap.trace(now, query, nil)
	}
	return t.tx.PrepareContext(ctx, query)
}

func (t *Transaction) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&query, args...)
	}

	args, err := t.dbmap.convertArgs(args...)
	if err != nil {
		return nil
	}

	if t.dbmap.logger != nil {
		now := time.Now()
		defer t.dbmap.trace(now, query, args...)
	}
	return t.tx.QueryRowContext(ctx, query, args...)
}

func (t *Transaction) QueryContext(ctx context.Context, q string, args ...interface{}) (*sql.Rows, error) {
	if t.dbmap.ExpandSliceArgs {
		expandSliceArgs(&q, args...)
	}

	args, err := t.dbmap.convertArgs(args...)
	if err != nil {
		return nil, err
	}

	if t.dbmap.logger != nil {
		now := time.Now()
		defer t.dbmap.trace(now, q, args...)
	}
	return t.tx.QueryContext(ctx, q, args...)
}
