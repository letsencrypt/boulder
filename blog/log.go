// This file contains all of the helper functions for emitting log messages. It
// is the primary public interface of this package. Each function extracts the
// logger from the context and uses it to log the given message and additional
// attrs.

package blog

import (
	"context"
	"log/slog"
)

// Error logs the given message, error, and other key-value pairs at error
// level. The error will be included in the attrs under the key "error".
func Error(ctx context.Context, msg string, err error, attrs ...slog.Attr) {
	slogger := fromContext(ctx).With(slog.Any("error", err))
	slogger.LogAttrs(ctx, slog.LevelError, msg, attrs...)
}

// Warn logs the given message and other key-value pairs at warning level.
func Warn(ctx context.Context, msg string, attrs ...slog.Attr) {
	slogger := fromContext(ctx)
	slogger.LogAttrs(ctx, slog.LevelWarn, msg, attrs...)
}

// Info logs the given message and other key-value pairs at info level.
func Info(ctx context.Context, msg string, err error, attrs ...slog.Attr) {
	slogger := fromContext(ctx)
	slogger.LogAttrs(ctx, slog.LevelInfo, msg, attrs...)
}

// Debug logs the given message and other key-value pairs at debug level.
func Debug(ctx context.Context, msg string, err error, attrs ...slog.Attr) {
	slogger := fromContext(ctx)
	slogger.LogAttrs(ctx, slog.LevelDebug, msg, attrs...)
}

// Error logs the given message, error, and other key-value pairs at error level
// and with the audit tag. The error will be included in the attrs under the key
// "error".
func AuditError(ctx context.Context, msg string, err error, attrs ...slog.Attr) {
	slogger := fromContext(ctx).With(auditAttr, slog.Any("error", err))
	slogger.LogAttrs(ctx, slog.LevelError, msg, attrs...)
}

// Info logs the given message and other key-value pairs at info level and with
// the audit tag.
func AuditInfo(ctx context.Context, msg string, attrs ...slog.Attr) {
	slogger := fromContext(ctx).With(auditAttr)
	slogger.LogAttrs(ctx, slog.LevelInfo, msg, attrs...)
}
