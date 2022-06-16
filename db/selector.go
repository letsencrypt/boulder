package db

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strings"
)

type typeSelector[T any] struct {
	wrapped MappedExecutor
}

// NewTypeSelector returns an object which can be used to automagically query
// the provided type-mapped database for rows of the parameterized type.
func NewTypeSelector[T any](wm MappedExecutor) *typeSelector[T] {
	return &typeSelector[T]{wrapped: wm}
}

// SelectRows combines the best features of gorp, the go stdlib, and generics.
// It uses the type parameter of the typeSelector object to automatically look
// up the proper table name and columns to select. It returns an iterable which
// yields fully-populated objects of the parameterized type directly. The given
// clauses MUST be only the bits of a sql query from "WHERE ..." onwards; if
// they contain any of the "SELECT ... FROM ..." portion of the query it will
// result in an error. The caller is responsible for calling `Rows.Close()`
// when they are done with the query.
func (ts typeSelector[T]) SelectRows(ctx context.Context, clauses string, args ...interface{}) (*typeRows[T], error) {
	// Look up the table to use based on the type of this TypeSelector.
	var t T
	tableMap, err := ts.wrapped.TableFor(reflect.TypeOf(t), false)
	if err != nil {
		return nil, fmt.Errorf("database model type not mapped to table name: %w", err)
	}

	return ts.SelectRowsFrom(ctx, tableMap.TableName, clauses, args...)
}

// SelectRowsFrom is the same as SelectRows, but it additionally takes a table
// name to select from, rather than automatically computing the table name from
// gorp's DbMap.
func (ts typeSelector[T]) SelectRowsFrom(ctx context.Context, tablename string, clauses string, args ...interface{}) (*typeRows[T], error) {
	// Look up the table to use based on the type of this TypeSelector.
	var throwaway T
	t := reflect.TypeOf(throwaway)
	tableMap, err := ts.wrapped.TableFor(t, false)
	if err != nil {
		return nil, fmt.Errorf("database model type not mapped to table name: %w", err)
	}

	// Extract the list of column names from the type's struct tags.
	var columns []string
	for _, column := range tableMap.Columns {
		columns = append(columns, column.ColumnName)
	}

	// Iterate over the columns in the order they appear. For each, find the field
	// on the struct type that has a matching `db:"colname"` struct tag. Save that
	// field's index into a map for quick lookup later.
	colIndexToFieldIndex := make([][]int, len(columns))
	for i, column := range columns {
		structField, found := t.FieldByNameFunc(func(fieldName string) bool {
			structField, _ := t.FieldByName(fieldName)
			tagColumn := structField.Tag.Get("db")
			return tagColumn == column
		})
		if !found {
			// This should never happen, as the columns were derived from the struct
			// fields in the first place.
			return nil, fmt.Errorf("no struct field with tag matching column %q", column)
		}
		colIndexToFieldIndex[i] = structField.Index
	}

	// Construct the query from the column names, table name, and given clauses.
	query := fmt.Sprintf(
		"SELECT %s FROM %s %s",
		strings.Join(columns, ", "),
		tablename,
		clauses,
	)

	rows, err := ts.wrapped.WithContext(ctx).Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("reading db: %w", err)
	}

	return &typeRows[T]{wrapped: rows, idxMap: colIndexToFieldIndex}, nil
}

// typeRows is a wrapper around the stdlib's sql.typeRows, but with a more
// type-safe method to get actual row content.
type typeRows[T any] struct {
	wrapped *sql.Rows
	idxMap  [][]int
}

// Next is a wrapper around sql.Rows.Next(). It must be called before every call
// to Get(), including the first.
func (r typeRows[T]) Next() bool {
	return r.wrapped.Next()
}

// Get is a wrapper around sql.Rows.Scan(). Rather than populating an arbitrary
// number of &interface{} arguments, it returns a populated object of the
// parameterized type.
func (r typeRows[T]) Get() (*T, error) {
	// We have to use reflect.New(reflect.TypeOf(var T)) to create our result
	// value to ensure that it gets allocated on the heap and its individual
	// fields are all addressable.
	var throwaway T
	t := reflect.TypeOf(throwaway)
	v := reflect.New(t)

	// Because sql.Rows.Scan(...) takes a variadic number of individual targets to
	// read values into, build a slice that can be splatted into the call. Use the
	// pre-computed map of column indices to field indices to populate it.
	scanTargets := make([]interface{}, len(r.idxMap))
	for i := range r.idxMap {
		field := v.Elem().FieldByIndex(r.idxMap[i])
		scanTargets[i] = field.Addr().Interface()
	}

	err := r.wrapped.Scan(scanTargets...)
	if err != nil {
		return nil, fmt.Errorf("reading db row: %w", err)
	}

	// Finally cast our *reflect.Value back into a T so we can return it.
	result := v.Elem().Interface().(T)
	return &result, nil
}

// Err is a wrapper around sql.Rows.Err(). It should be checked immediately
// after Next() returns false for any reason.
func (r typeRows[T]) Err() error {
	return r.wrapped.Err()
}

// Close is a wrapper around sql.Rows.Close(). It must be called when the caller
// is done reading rows, regardless of success or error.
func (r typeRows[T]) Close() error {
	return r.wrapped.Close()
}
