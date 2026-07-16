package blog

// This file provides a slog.Handler which routes each record to the syslog
// severity matching the record's slog level. The stdlib syslog.Writer applies
// its dial-time priority to every plain Write call, so if we treated it as a
// simple io.Writer then every line, including errors and audit errors, would
// arrive at syslog with severity INFO, breaking any downstream routing or
// alerting keyed on syslog severity (e.g. rsyslog "*.err" selectors). Instead
// we build one full handler chain per severity, each bottoming out in the
// severity-specific method (Err, Warning, Info, Debug) on the shared
// syslog.Writer, and dispatch each record to the chain matching its level.

import (
	"context"
	"io"
	"log/slog"
	"log/syslog"
)

// syslogWriter is the subset of *syslog.Writer used by severityHandler. It
// exists so that tests can substitute a fake.
type syslogWriter interface {
	Err(string) error
	Warning(string) error
	Info(string) error
	Debug(string) error
}

var _ syslogWriter = (*syslog.Writer)(nil)

// severityWriter adapts one severity-specific method of a syslog.Writer to the
// io.Writer interface expected by the checksum and audit writers.
type severityWriter struct {
	fn func(string) error
}

var _ io.Writer = (*severityWriter)(nil)

// Write implements the io.Writer interface. It forwards its input to the
// wrapped severity-specific syslog method, which serializes concurrent calls
// with the syslog.Writer's internal mutex.
func (w *severityWriter) Write(in []byte) (int, error) {
	return len(in), w.fn(string(in))
}

// severityHandler is a slog.Handler which dispatches each record to one of four
// wrapped handlers based on the record's level, so that each line reaches
// syslog with the matching severity. It tracks the configured minimum level
// itself, so the wrapped handlers do no level filtering of their own.
type severityHandler struct {
	level slog.Level
	err   slog.Handler
	warn  slog.Handler
	info  slog.Handler
	debug slog.Handler
}

var _ slog.Handler = (*severityHandler)(nil)

// newSeverityHandler builds a severityHandler over the given syslog writer.
// The confLevel argument is the syslog-style (0-7) level from our Config.
func newSeverityHandler(w syslogWriter, confLevel int) *severityHandler {
	build := func(fn func(string) error) slog.Handler {
		// configToSlogLevel never returns a level below LevelDebug, so these
		// chains accept every record that severityHandler.Enabled accepts.
		// Each chain gets its own HandlerOptions because newAuditHandler
		// modifies opts.ReplaceAttr in place.
		opts := &slog.HandlerOptions{Level: slog.LevelDebug}
		return newAuditHandler(newChecksumWriter(&severityWriter{fn: fn}), opts)
	}
	return &severityHandler{
		level: configToSlogLevel(confLevel),
		err:   build(w.Err),
		warn:  build(w.Warning),
		info:  build(w.Info),
		debug: build(w.Debug),
	}
}

// Enabled reports whether records at the given level would be handled.
func (h *severityHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level
}

// Handle dispatches the record to the wrapped handler whose syslog severity
// matches the record's level.
func (h *severityHandler) Handle(ctx context.Context, r slog.Record) error {
	switch {
	case r.Level >= slog.LevelError:
		return h.err.Handle(ctx, r)
	case r.Level >= slog.LevelWarn:
		return h.warn.Handle(ctx, r)
	case r.Level >= slog.LevelInfo:
		return h.info.Handle(ctx, r)
	default:
		return h.debug.Handle(ctx, r)
	}
}

// WithAttrs calls WithAttrs on all wrapped handlers.
func (h *severityHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &severityHandler{
		level: h.level,
		err:   h.err.WithAttrs(attrs),
		warn:  h.warn.WithAttrs(attrs),
		info:  h.info.WithAttrs(attrs),
		debug: h.debug.WithAttrs(attrs),
	}
}

// WithGroup calls WithGroup on all wrapped handlers.
func (h *severityHandler) WithGroup(name string) slog.Handler {
	return &severityHandler{
		level: h.level,
		err:   h.err.WithGroup(name),
		warn:  h.warn.WithGroup(name),
		info:  h.info.WithGroup(name),
		debug: h.debug.WithGroup(name),
	}
}
