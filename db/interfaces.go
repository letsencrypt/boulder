package db

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"

	"github.com/letsencrypt/borp"
)

// These interfaces exist to aid in mocking database operations for unit tests.
//
// By convention, any function that takes a OneSelector, Selector,
// Inserter, Execer, or SelectExecer as as an argument expects
// that a context has already been applied to the relevant DbMap or
// Transaction object.

// A OneSelector is anything that provides a `SelectOne` function.
type OneSelector interface {
	SelectOne(context.Context, any, string, ...any) error
}

// A Selector is anything that provides a `Select` function.
type Selector interface {
	Select(context.Context, any, string, ...any) ([]any, error)
}

// A Inserter is anything that provides an `Insert` function
type Inserter interface {
	Insert(context.Context, ...any) error
}

// A Execer is anything that provides an `ExecContext` function
type Execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// SelectExecer offers a subset of borp.SqlExecutor's methods: Select and
// ExecContext.
type SelectExecer interface {
	Selector
	Execer
}

// DatabaseMap offers the full combination of OneSelector, Inserter,
// SelectExecer, and a Begin function for creating a Transaction.
type DatabaseMap interface {
	OneSelector
	Inserter
	SelectExecer
	BeginTx(context.Context) (Transaction, error)
}

// Executor offers the full combination of OneSelector, Inserter, SelectExecer
// and adds a handful of other high level borp methods we use in Boulder.
type Executor interface {
	OneSelector
	Inserter
	SelectExecer
	Delete(context.Context, ...any) (int64, error)
	Get(context.Context, any, ...any) (any, error)
	Update(context.Context, ...any) (int64, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// Transaction extends an Executor and adds Rollback and Commit
type Transaction interface {
	Executor
	Rollback() error
	Commit() error
}

// MappedExecutor is anything that can map types to tables
type MappedExecutor interface {
	TableFor(reflect.Type, bool) (*borp.TableMap, error)
	QueryContext(ctx context.Context, clauses string, args ...any) (*sql.Rows, error)
}

// MappedSelector is anything that can execute various kinds of SQL statements
// against a table automatically determined from the parameterized type.
type MappedSelector[T any] interface {
	QueryContext(ctx context.Context, clauses string, args ...any) (Rows[T], error)
	QueryFrom(ctx context.Context, tablename string, clauses string, args ...any) (Rows[T], error)
}

// Rows is anything which lets you iterate over the result rows of a SELECT
// query. It is similar to sql.Rows, but generic.
type Rows[T any] interface {
	ForEach(func(*T) error) error
	Next() bool
	Get() (*T, error)
	Err() error
	Close() error
}

// MockSqlExecutor implement SqlExecutor by returning errors from every call.
//
// TODO: To mock out WithContext, we needed to be able to return objects that satisfy
// borp.SqlExecutor. That's a pretty big interface, so we specify one no-op mock
// that we can embed everywhere we need to satisfy it.
// Note: MockSqlExecutor does *not* implement WithContext. The expectation is
// that structs that embed MockSqlExecutor will define their own WithContext
// that returns a reference to themselves. That makes it easy for those structs
// to override the specific methods they need to implement (e.g. SelectOne).
type MockSqlExecutor struct{}

func (mse MockSqlExecutor) Get(ctx context.Context, i any, keys ...any) (any, error) {
	return nil, fmt.Errorf("unimplemented")
}
func (mse MockSqlExecutor) Insert(ctx context.Context, list ...any) error {
	return fmt.Errorf("unimplemented")
}
func (mse MockSqlExecutor) Update(ctx context.Context, list ...any) (int64, error) {
	return 0, fmt.Errorf("unimplemented")
}
func (mse MockSqlExecutor) Delete(ctx context.Context, list ...any) (int64, error) {
	return 0, fmt.Errorf("unimplemented")
}
func (mse MockSqlExecutor) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return nil, fmt.Errorf("unimplemented")
}
func (mse MockSqlExecutor) Select(ctx context.Context, i any, query string, args ...any) ([]any, error) {
	return nil, fmt.Errorf("unimplemented")
}
func (mse MockSqlExecutor) SelectInt(ctx context.Context, query string, args ...any) (int64, error) {
	return 0, fmt.Errorf("unimplemented")
}
func (mse MockSqlExecutor) SelectNullInt(ctx context.Context, query string, args ...any) (sql.NullInt64, error) {
	return sql.NullInt64{}, fmt.Errorf("unimplemented")
}
func (mse MockSqlExecutor) SelectFloat(ctx context.Context, query string, args ...any) (float64, error) {
	return 0, fmt.Errorf("unimplemented")
}
func (mse MockSqlExecutor) SelectNullFloat(ctx context.Context, query string, args ...any) (sql.NullFloat64, error) {
	return sql.NullFloat64{}, fmt.Errorf("unimplemented")
}
func (mse MockSqlExecutor) SelectStr(ctx context.Context, query string, args ...any) (string, error) {
	return "", fmt.Errorf("unimplemented")
}
func (mse MockSqlExecutor) SelectNullStr(ctx context.Context, query string, args ...any) (sql.NullString, error) {
	return sql.NullString{}, fmt.Errorf("unimplemented")
}
func (mse MockSqlExecutor) SelectOne(ctx context.Context, holder any, query string, args ...any) error {
	return fmt.Errorf("unimplemented")
}
func (mse MockSqlExecutor) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return nil, fmt.Errorf("unimplemented")
}
func (mse MockSqlExecutor) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return nil
}
