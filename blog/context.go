// This file provides
// This file provides utilities for attaching a logger to a context object, and
// retrieving a logger from a context object. These are unexported, as other
// packages should not be directly manipulating the context logger.
//
// It also provides one exported function for attaching new attrs to the context
// logger, so they'll be included in all subsequent log lines.

package blog

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"log/syslog"
	"os"

	"github.com/letsencrypt/boulder/core"
)

// sloggerCtxKeyType exists to ensure that sloggerCtxKey is a wholly unique
// singleton that cannot collide with context keys used by other packages.
type sloggerCtxKeyType struct{}

// sloggerCtxKey is the unique key used by this package to store and retrieve
// the logger on a context.Context.
var sloggerCtxKey = sloggerCtxKeyType{}

// LogContext is the only struct exported by this package. It contains a
// slog.Logger, and can be stored (e.g. on an gRPC impl struct) to provide
// continuous access to that logger. However, it only provides access to that
// logger by virtue of producing context.Context objects which can be passed
// into this package's primary interface functions, such as blog.Info and
// blog.ContextWith.
//
// Most code shouldn't need to concern itself with this type, as most code (e.g.
// gRPC and HTTP request handlers) should receive a context with a logger
// already attached. This type is only necessary for non-request-based code,
// such as the request interceptors which attach a logger to each request's
// context, server startup code, and crl-updater.
type LogContext struct {
	logger *slog.Logger
}

// NewLogContext returns a LogContext which can be used to produce context
// objects containing the configured logger. The logger prepends the [AUDIT] tag
// to audit messages, prepends a checksum to all messages, and then writes log
// messages to stdout and syslog as configured.
//
// Cannot error if only the stdout logger has a non-negative log level.
func NewLogContext(conf Config) (*LogContext, error) {
	var stdoutHandler slog.Handler
	if conf.StdoutLevel >= 0 {
		writer := newChecksumWriter(os.Stdout)
		opts := &slog.HandlerOptions{Level: configToSlogLevel(conf.StdoutLevel)}
		if conf.TextFormat {
			stdoutHandler = newAuditHandler(slog.NewTextHandler, writer, opts)
		} else {
			stdoutHandler = newAuditHandler(slog.NewJSONHandler, writer, opts)
		}
	}

	var syslogHandler slog.Handler
	if conf.SyslogLevel >= 0 {
		syslogger, err := syslog.Dial("", "", syslog.LOG_INFO, core.Command())
		if err != nil {
			return nil, fmt.Errorf("failed to connect to syslog: %w", err)
		}

		writer := newChecksumWriter(syslogger)
		opts := &slog.HandlerOptions{Level: configToSlogLevel(conf.SyslogLevel)}
		if conf.TextFormat {
			syslogHandler = newAuditHandler(slog.NewTextHandler, writer, opts)
		} else {
			syslogHandler = newAuditHandler(slog.NewJSONHandler, writer, opts)
		}
	}

	var l *slog.Logger
	switch {
	case stdoutHandler != nil && syslogHandler != nil:
		l = slog.New(newMultiHandler(stdoutHandler, syslogHandler))
	case stdoutHandler != nil:
		l = slog.New(stdoutHandler)
	case syslogHandler != nil:
		l = slog.New(syslogHandler)
	default:
		return nil, errors.New("either StdoutLevel or SyslogLevel must be positive")
	}

	return &LogContext{logger: l}, nil
}

// New returns a new context with the logger attached.
func (c *LogContext) New() context.Context {
	return c.Attach(context.Background())
}

// Attach returns a new context derived from the given context, with the logger
// attached.
func (c *LogContext) Attach(ctx context.Context) context.Context {
	return context.WithValue(ctx, sloggerCtxKey, c.logger)
}

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
