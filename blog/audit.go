// This file provides the scaffolding necessary to differentiate audit logs from
// non-audit logs. This consists of four parts:
//
// 1. A singleton slog.Attr which can be attached to audit records by the
//    AuditLevel helper functions.
// 2. A Handler which contains two different sub-handlers, and which dispatches
//    each Record to one of those handlers depending on whether that Record
//    contains the singleton audit Attr.
// 3. An io.Writer which prepends the text `[AUDIT] ` to all messages written
//    to it.
// 4. Finally, a constructor which accepts the same arguments as slog's
//    NewTextHandler and NewJSONHandler and builds two copies of the handler,
//    one of which has its writer wrapped in the auditWriter.

package blog

import (
	"bytes"
	"context"
	"io"
	"log/slog"
)

// auditKey is the key used to identify the auditAttr.
const auditKey = "audit"

// auditAttr is a singleton slog.Attr which is added to Records by AuditError
// and AuditInfo, and detected on records by auditHandler.Handle to decide
// which sub-Handler the Record should be routed to.
var auditAttr = slog.Bool(auditKey, true)

// auditWriter implements the io.Writer interface. It prepends the string
// `[AUDIT] ` to each line written to it.
type auditWriter struct {
	inner io.Writer
}

var _ io.Writer = (*auditWriter)(nil)

// Write implements the io.Writer interface. It prepends the string `[AUDIT] `
// to its input and forwards the result to the inner io.Writer.
//
// The slog package guarantees that "each call to Handle results in a single
// serialized call to io.Writer.Write". Similarly, each call to this method also
// results in a single call to the wrapped io.Writer.Write. This means that we
// are prepending the audit tag exactly once per call to slog.Logger.Handle.
func (w *auditWriter) Write(in []byte) (int, error) {
	out := bytes.Buffer{}
	out.WriteString("[AUDIT] ")
	out.Write(in)
	size, err := out.WriteTo(w.inner)
	return int(size), err
}

// newAuditHandler creates an auditHandler, using the given constructor and
// arguments to build the underlying slog.Handlers it will wrap. It wraps the
// given io.Writer in an auditWriter for one of the two Handlers it builds. It
// has to be generic because Go can't cast a `func(...) *slog.TextHandler` to a
// `func(...) slog.Handler`.
func newAuditHandler[T slog.Handler](constructor func(io.Writer, *slog.HandlerOptions) T, w io.Writer, opts *slog.HandlerOptions) *auditHandler {
	origReplaceAttr := opts.ReplaceAttr
	opts.ReplaceAttr = func(groups []string, attr slog.Attr) slog.Attr {
		// Since the auditWriter will add the [AUDIT] tag to its log lines, we don't
		// want to log the audit=true attr itself. We check for full equality here,
		// whereas Handle just checks for auditKey, to avoid dropping anything if
		// someone accidentally and incorrectly adds an attr like
		// slog.String("audit", "Here's some really important text").
		if attr.Equal(auditAttr) {
			return slog.Attr{}
		}
		if origReplaceAttr != nil {
			return origReplaceAttr(groups, attr)
		}
		return attr
	}

	return &auditHandler{
		audit: constructor(&auditWriter{inner: w}, opts),
		plain: constructor(w, opts),
	}
}

// auditHandler is a slog.Handler whose Enabled, WithAttr, and WithGroup methods
// call the corresponding methods on each of the wrapped Handlers, but whose
// Handle method calls the corresponding method only on one or the other of the
// wrapped Handlers, depending on whether the slog.Record indicates that this
// log line is an audit log or not.
type auditHandler struct {
	audit slog.Handler
	plain slog.Handler
}

var _ slog.Handler = (*auditHandler)(nil)

// Enabled returns true if either wrapped handler is enabled. Both wrapped
// Handlers should have been constructed with the same HandlerOptions, and
// therefore the same Leveler, so there should never be a discrepancy.
func (h *auditHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.audit.Enabled(ctx, l) || h.plain.Enabled(ctx, l)
}

// Handle calls Handle on either the wrapped audit Handler or the wrapped plain
// Handler, depending on whether or not the input Record contains an attr with
// the audit key.
func (h *auditHandler) Handle(ctx context.Context, r slog.Record) error {
	handler := h.plain
	for attr := range r.Attrs {
		if attr.Key == auditKey {
			handler = h.audit
			break
		}
	}
	return handler.Handle(ctx, r)
}

// WithAttrs calls WithAttrs on both wrapped Handlers.
func (h *auditHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &auditHandler{
		audit: h.audit.WithAttrs(attrs),
		plain: h.plain.WithAttrs(attrs),
	}
}

// WithGroup calls WithGroup on both wrapped Handlers.
func (h *auditHandler) WithGroup(name string) slog.Handler {
	return &auditHandler{
		audit: h.audit.WithGroup(name),
		plain: h.plain.WithGroup(name),
	}
}
