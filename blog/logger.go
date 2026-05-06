package blog

// This file defines the core interface of the blog package: blog.Logger, and
// its constructor, blog.New. This type has methods for emitting logs at each
// level, and for emitting audit logs at the info and error levels. It is
// expected that users of this package will create a single top-level logger,
// store it on a persistent object (such as a gRPC or HTTP handler struct),
// attach relevant attributes to a context.Context which flows through methods
// on that struct, and pass the context to the stored logger at each call site.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"log/syslog"
	"os"

	"github.com/letsencrypt/boulder/core"
)

// Logger is a wrapper around slog.Logger. It exposes methods whose signatures
// require that a context be provided (from which slog Attrs will be extracted),
// and that any additional attributes be presented as slog.Attrs (not as
// comma-separated keys and values). It does not provide affordances for
// deriving a child logger with additional attrs attached; calling code should
// attach such persistent attributes to its context object instead.
type Logger interface {
	Error(context.Context, string, error, ...slog.Attr)
	Warn(context.Context, string, ...slog.Attr)
	Info(context.Context, string, ...slog.Attr)
	Debug(context.Context, string, ...slog.Attr)
	AuditError(context.Context, string, error, ...slog.Attr)
	AuditInfo(context.Context, string, ...slog.Attr)
}

// logger implements the Logger interface.
type logger struct {
	inner *slog.Logger
}

// New returns a Logger per the config. The logger extracts slog.Attrs from the
// context, prepends the [AUDIT] tag to calls to its Audit* methods, prepends a
// checksum to all messages, and then writes the resulting log messages to
// stdout and/or syslog as configured.
//
// Cannot error if only the stdout logger is enabled (has a non-negative level).
func New(conf Config) (*logger, error) {
	var stdoutHandler slog.Handler
	if conf.StdoutLevel > 0 {
		writer := newChecksumWriter(os.Stdout)
		opts := &slog.HandlerOptions{Level: configToSlogLevel(conf.StdoutLevel)}
		stdoutHandler = &contextHandler{inner: newAuditHandler(writer, opts)}
	}

	var syslogHandler slog.Handler
	if conf.SyslogLevel == 0 {
		conf.SyslogLevel = 6
	}
	if conf.SyslogLevel > 0 {
		syslogger, err := syslog.Dial("", "", syslog.LOG_INFO, core.Command())
		if err != nil {
			return nil, fmt.Errorf("failed to connect to syslog: %w", err)
		}

		writer := newChecksumWriter(syslogger)
		opts := &slog.HandlerOptions{Level: configToSlogLevel(conf.SyslogLevel)}
		syslogHandler = &contextHandler{inner: newAuditHandler(writer, opts)}
	}

	var l *slog.Logger
	switch {
	case stdoutHandler != nil && syslogHandler != nil:
		l = slog.New(slog.NewMultiHandler(stdoutHandler, syslogHandler))
	case stdoutHandler != nil:
		l = slog.New(stdoutHandler)
	case syslogHandler != nil:
		l = slog.New(syslogHandler)
	default:
		return nil, errors.New("either StdoutLevel or SyslogLevel must be positive")
	}

	l = l.With(universalAttrs()...)

	return &logger{inner: l}, nil
}

// Error logs the given message, error, and other key-value pairs at error
// level. The error will be included in the attrs under the key "error".
func (l *logger) Error(ctx context.Context, msg string, err error, attrs ...slog.Attr) {
	// We attach these attrs to the context, rather than passing them directly to
	// LogAttrs, to ensure that they come last in the log line. See
	// contextHandler.Handle() for more information.
	ctx = ContextWith(ctx, append(attrs, Error(err))...)
	l.inner.LogAttrs(ctx, slog.LevelError, msg)
}

// Warn logs the given message and other key-value pairs at warning level.
func (l *logger) Warn(ctx context.Context, msg string, attrs ...slog.Attr) {
	ctx = ContextWith(ctx, attrs...)
	l.inner.LogAttrs(ctx, slog.LevelWarn, msg)
}

// Info logs the given message and other key-value pairs at info level.
func (l *logger) Info(ctx context.Context, msg string, attrs ...slog.Attr) {
	ctx = ContextWith(ctx, attrs...)
	l.inner.LogAttrs(ctx, slog.LevelInfo, msg)
}

// Debug logs the given message and other key-value pairs at debug level.
func (l *logger) Debug(ctx context.Context, msg string, attrs ...slog.Attr) {
	ctx = ContextWith(ctx, attrs...)
	l.inner.LogAttrs(ctx, slog.LevelDebug, msg)
}

// AuditError logs the given message, error, and other key-value pairs at error
// level and with the audit tag. The error will be included in the attrs under
// the key "error".
func (l *logger) AuditError(ctx context.Context, msg string, err error, attrs ...slog.Attr) {
	ctx = ContextWith(ctx, append(attrs, auditAttr, Error(err))...)
	l.inner.LogAttrs(ctx, slog.LevelError, msg)
}

// AuditInfo logs the given message and other key-value pairs at info level and
// with the audit tag.
func (l *logger) AuditInfo(ctx context.Context, msg string, attrs ...slog.Attr) {
	ctx = ContextWith(ctx, append(attrs, auditAttr)...)
	l.inner.LogAttrs(ctx, slog.LevelInfo, msg)
}
