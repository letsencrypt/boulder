// Copyright 2012 James Cooper. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package gorp provides a simple way to marshal Go structs to and from
// SQL databases.  It uses the database/sql package, and should work with any
// compliant database/sql driver.
//
// Source code and project home:
// https://github.com/go-gorp/gorp
//

// +build go1.8

package gorp

import (
	"context"
	"database/sql"
)

// executor exposes the sql.DB and sql.Tx functions so that it can be used
// on internal functions that need to be agnostic to the underlying object.
type executor interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Prepare(query string) (*sql.Stmt, error)
	QueryRow(query string, args ...interface{}) *sql.Row
	Query(query string, args ...interface{}) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
}

func exec(e SqlExecutor, query string, args ...interface{}) (sql.Result, error) {
	executor, ctx := extractExecutorAndContext(e)

	if ctx != nil {
		return executor.ExecContext(ctx, query, args...)
	}

	return executor.Exec(query, args...)
}

func prepare(e SqlExecutor, query string) (*sql.Stmt, error) {
	executor, ctx := extractExecutorAndContext(e)

	if ctx != nil {
		return executor.PrepareContext(ctx, query)
	}

	return executor.Prepare(query)
}

func queryRow(e SqlExecutor, query string, args ...interface{}) *sql.Row {
	executor, ctx := extractExecutorAndContext(e)

	if ctx != nil {
		return executor.QueryRowContext(ctx, query, args...)
	}

	return executor.QueryRow(query, args...)
}

func query(e SqlExecutor, query string, args ...interface{}) (*sql.Rows, error) {
	executor, ctx := extractExecutorAndContext(e)

	if ctx != nil {
		return executor.QueryContext(ctx, query, args...)
	}

	return executor.Query(query, args...)
}

func begin(m *DbMap) (*sql.Tx, error) {
	if m.ctx != nil {
		return m.Db.BeginTx(m.ctx, nil)
	}

	return m.Db.Begin()
}
