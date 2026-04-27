//go:build integration

package blog

// This file is used by the integration tests.

import (
	"io"
	"log/slog"

	"github.com/letsencrypt/boulder/core"
)

// stdlibHandler constructs the underlying handler provided by the go
// standard library appropriate to the current environment.
//
// In integration tests, we always use the TextHandler.
func stdlibHandler(w io.Writer, opts *slog.HandlerOptions) slog.Handler {
	return slog.NewTextHandler(w, opts)
}

// universalAttrs returns the set of slog.Attrs which should be included in all
// log lines. It returns []any instead of []slog.Attr because slog doesn't have
// a Logger.WithAttr() method.
//
// Because this is used only in the test environment, it returns a minimal set.
func universalAttrs() []any {
	return []any{slog.String("prog", core.Command())}
}
