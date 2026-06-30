//go:build !integration

package blog

// This file is used by production code and unit tests.

import (
	"io"
	"log/slog"
	"testing"
)

// stdlibHandler constructs the underlying handler provided by the go
// standard library appropriate to the current environment.
//
// In unit tests, we use the TextHandler for ease of assertion readability.
// In actual production code, we use the JSONHandler.
func stdlibHandler(w io.Writer, opts *slog.HandlerOptions) slog.Handler {
	if testing.Testing() {
		return slog.NewTextHandler(w, opts)
	} else {
		return slog.NewJSONHandler(w, opts)
	}
}

// universalAttrs returns the set of slog.Attrs which should be included in all
// log lines. It returns []any instead of []slog.Attr because slog doesn't have
// a Logger.WithAttr() method.
//
// Because our production log collector adds dc/host/prog/pid tags itself, we
// don't add anything here.
func universalAttrs() []any {
	return nil
}
