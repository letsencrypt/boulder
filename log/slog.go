package log

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"log/syslog"
	"os"

	"github.com/letsencrypt/boulder/core"
)

// SlogConfig defines the config for logging to syslog and stdout/stderr. The
// level meanings are as follows:
//
//	-1: suppress all output
//	0: default, which is 6
//	1: meaningless
//	2: meaningless
//	3: log errors
//	4: log warnings and above
//	5: meaningless
//	6: log info and above
//	7: log debug and above
//
// The structure of this config object is a superset of cmd.SyslogConfig, so
// that the same existing json objects can be parsed into it.
type SlogConfig struct {
	// When absent or zero, this causes no logs to be emitted on stdout/stderr.
	// Errors and warnings will be emitted on stderr if the configured level
	// allows.
	StdoutLevel int `validate:"min=-1,max=7"`
	// When absent or zero, this defaults to logging all messages of level 6
	// or below. To disable syslog logging entirely, set this to -1.
	SyslogLevel int `validate:"min=-1,max=7"`
	// TextFormat causes logs to be output via slog's TextHandler instead of the
	// default JSONHandler. This is useful for log readability in local dev.
	TextFormat bool
}

// syslogToSlogLevelMap allows us to map the integers used in our log config
// (which originally come from syslog levels) to the values used by slog.
func configToSlogLevel(l int) slog.Level {
	switch l {
	case 1, 2, 3:
		return slog.LevelError
	case 4, 5:
		return slog.LevelWarn
	case 6:
		return slog.LevelInfo
	case 7:
		return slog.LevelDebug
	default:
		return slog.LevelInfo
	}
}

// NewSlogger returns a slog.Logger which writes log messages to stdout and
// syslog as configured.
func NewSlogger(conf SlogConfig) (*slog.Logger, error) {
	var stdoutHandler slog.Handler
	if conf.StdoutLevel >= 0 {
		writer := NewChecksumWriter(os.Stdout)
		opts := &slog.HandlerOptions{Level: configToSlogLevel(conf.StdoutLevel)}
		if conf.TextFormat {
			stdoutHandler = slog.NewTextHandler(writer, opts)
		} else {
			stdoutHandler = slog.NewJSONHandler(writer, opts)
		}
	}

	var syslogHandler slog.Handler
	if conf.SyslogLevel >= 0 {
		syslogger, err := syslog.Dial("", "", syslog.LOG_INFO, core.Command())
		if err != nil {
			return nil, fmt.Errorf("failed to connect to syslog: %w", err)
		}

		writer := NewChecksumWriter(syslogger)
		opts := &slog.HandlerOptions{Level: configToSlogLevel(conf.SyslogLevel)}
		if conf.TextFormat {
			syslogHandler = slog.NewTextHandler(writer, opts)
		} else {
			syslogHandler = slog.NewJSONHandler(writer, opts)
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

	return l, nil
}

var sloggerContextKey = struct{}{}

func ContextWith(ctx context.Context, pairs ...any) context.Context {
	slogger := fromContext(ctx).With(pairs...)
	return context.WithValue(ctx, sloggerContextKey, slogger)
}

func fromContext(ctx context.Context) *slog.Logger {
	slogger, ok := ctx.Value(sloggerContextKey).(*slog.Logger)
	if slogger == nil || !ok {
		panic("context not initialized with slogger")
	}
	return slogger
}

func Error(ctx context.Context, msg string, err error, attrs ...slog.Attr) {
	slogger := fromContext(ctx).With(slog.Any("error", err))
	slogger.LogAttrs(ctx, slog.LevelError, msg, attrs...)
}

func Warn(ctx context.Context, msg string, attrs ...slog.Attr) {
	slogger := fromContext(ctx)
	slogger.LogAttrs(ctx, slog.LevelWarn, msg, attrs...)
}

func Info(ctx context.Context, msg string, err error, attrs ...slog.Attr) {
	slogger := fromContext(ctx)
	slogger.LogAttrs(ctx, slog.LevelInfo, msg, attrs...)
}

func Debug(ctx context.Context, msg string, err error, attrs ...slog.Attr) {
	slogger := fromContext(ctx)
	slogger.LogAttrs(ctx, slog.LevelDebug, msg, attrs...)
}
