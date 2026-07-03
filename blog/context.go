package blog

// This file provides an exported utility for attaching slog.Attrs to a context
// object, so that they will be included in all subsequent log output.
//
// It also implements a slog.Handler which extracts stored attrs from a context
// and includes them in the resulting log line. This handler is always included
// as part of the handler chain in blog.New().

import (
	"context"
	"log/slog"
	"slices"
)

// sloggerCtxKeyType exists to ensure that sloggerCtxKey is a wholly unique
// singleton that cannot collide with context keys used by other packages.
type sloggerCtxKeyType struct{}

// sloggerCtxKey is the unique key used by this package to store and retrieve
// the slog.Attrs stored on a context.Context.
var sloggerCtxKey = sloggerCtxKeyType{}

// fromContext retrieves the slog.Attrs from the context. It returns a copy to
// prevent callers from accidentally modifying the context's attrs in place. It
// returns nil if no attributes are attached.
func fromContext(ctx context.Context) []slog.Attr {
	attrs, ok := ctx.Value(sloggerCtxKey).([]slog.Attr)
	if attrs == nil || !ok {
		return nil
	}
	return slices.Clone(attrs)
}

// ContextWith returns a new context with the given attributes attached, in
// addition to any already-attached attrs. All subsequent log calls to which the
// resulting context is passed will include the provided slog.Attrs.
func ContextWith(ctx context.Context, attrs ...slog.Attr) context.Context {
	a := append(fromContext(ctx), attrs...)
	return context.WithValue(ctx, sloggerCtxKey, a)
}

// contextHandler wraps another slog.Handler, extracting slog.Attrs from the
// context passed to Handle calls and attaching them to the resulting Record.
type contextHandler struct {
	inner slog.Handler
}

// Enabled reports whether the inner handler handles records at the given level.
func (c *contextHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return c.inner.Enabled(ctx, l)
}

// Handle extracts the attributes attached to the context object, attaches them
// to the Record, and then passes it through to the underlying Handler.
//
// Order matters. Attributes from the Context will be emitted after any
// attributes already present in the Record. Callers that want a given attribute
// to be emitted last in log lines (e.g. an error) should ensure that attribute
// is (a) provided in the Context and (b) the last in the Context's list of
// attributes. See the logger.Error() implementation in this package for an
// example.
func (c *contextHandler) Handle(ctx context.Context, r slog.Record) error {
	r = r.Clone()
	r.AddAttrs(fromContext(ctx)...)
	return c.inner.Handle(ctx, r)
}

// WithAttrs returns a new contextHandler wrapping the inner handler with the
// given attrs added. We must implement this (rather than relying on embedding)
// so that the resulting handler remains a contextHandler, preserving context
// attr extraction in downstream slog.Logger.With calls.
func (c *contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextHandler{inner: c.inner.WithAttrs(attrs)}
}

// WithGroup returns a new contextHandler wrapping the inner handler with the
// given group name. See WithAttrs for why we implement this explicitly.
func (c *contextHandler) WithGroup(name string) slog.Handler {
	return &contextHandler{inner: c.inner.WithGroup(name)}
}
