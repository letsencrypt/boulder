// This file provides utilities for attaching a logger to a context object, and
// retrieving a logger from a context object. These are unexported, as other
// packages should not be directly manipulating the context logger.
//
// It also provides one exported function for attaching new attrs to the context
// logger, so they'll be included in all subsequent log lines.

package blog

import (
	"context"
	"log/slog"
)

// sloggerCtxKeyType exists to ensure that sloggerCtxKey is a wholly unique
// singleton that cannot collide with context keys used by other packages.
type sloggerCtxKeyType struct{}

// sloggerCtxKey is the unique key used by this package to store and retrieve
// the logger on a context.Context.
var sloggerCtxKey = sloggerCtxKeyType{}

// fromContext retrieves the logger from the context. It panics if there is
// no logger attached.
func fromContext(ctx context.Context) *slog.Logger {
	slogger, ok := ctx.Value(sloggerCtxKey).(*slog.Logger)
	if slogger == nil || !ok {
		panic("context not initialized with slogger")
	}
	return slogger
}

// ContextWith returns a new context whose attached slogger will subsequently
// include the provided slog.Attrs in its log output.
func ContextWith(ctx context.Context, attrs ...slog.Attr) context.Context {
	// The underlying slog.Logger.With takes a []any rather than a []slog.Attr.
	// That would require us to translate this function's []slog.Attr argument
	// into a []any, since Go can't do that type coercion itself (because any is
	// an interface type and therefore requires a reallocation). Instead, we use
	// slog.GroupAttrs, which does take a []slog.Attr as its argument, and give it
	// the empty string as its key, causing all of the provided attrs to appear as
	// top-level attrs rather than nested under a group label. See
	// https://github.com/golang/go/issues/66937 for more reading.
	slogger := fromContext(ctx).With(slog.GroupAttrs("", attrs...))
	return context.WithValue(ctx, sloggerCtxKey, slogger)
}
