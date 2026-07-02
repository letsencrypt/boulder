package blog

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// fakeSyslog records which severity-specific method each line arrived on.
type fakeSyslog struct {
	mu    sync.Mutex
	lines map[string][]string
}

func newFakeSyslog() *fakeSyslog {
	return &fakeSyslog{lines: make(map[string][]string)}
}

func (f *fakeSyslog) record(severity, m string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lines[severity] = append(f.lines[severity], m)
	return nil
}

func (f *fakeSyslog) Err(m string) error     { return f.record("err", m) }
func (f *fakeSyslog) Warning(m string) error { return f.record("warning", m) }
func (f *fakeSyslog) Info(m string) error    { return f.record("info", m) }
func (f *fakeSyslog) Debug(m string) error   { return f.record("debug", m) }

var _ syslogWriter = (*fakeSyslog)(nil)

func TestSeverityHandlerRouting(t *testing.T) {
	t.Parallel()

	// Each log level must reach syslog via the matching severity-specific
	// method, so that the syslog-layer severity (used by rsyslog routing and
	// alerting) matches the level inside the message.
	fake := newFakeSyslog()
	l := &logger{inner: slog.New(&contextHandler{inner: newSeverityHandler(fake, 7)})}
	ctx := context.Background()

	l.Error(ctx, "an error", errors.New("boom"))
	l.AuditError(ctx, "an audit error", errors.New("bang"))
	l.Warn(ctx, "a warning")
	l.Info(ctx, "some info")
	l.AuditInfo(ctx, "some audit info")
	l.Debug(ctx, "some detail")

	fake.mu.Lock()
	defer fake.mu.Unlock()

	for severity, wantMsgs := range map[string][]string{
		"err":     {"an error", "an audit error"},
		"warning": {"a warning"},
		"info":    {"some info", "some audit info"},
		"debug":   {"some detail"},
	} {
		got := fake.lines[severity]
		if len(got) != len(wantMsgs) {
			t.Fatalf("severity %q received %d lines, want %d: %v", severity, len(got), len(wantMsgs), got)
		}
		for i, want := range wantMsgs {
			if !strings.Contains(got[i], want) {
				t.Errorf("severity %q line %d = %q, does not contain %q", severity, i, got[i], want)
			}
		}
	}

	// Audit lines must retain their [AUDIT] tag and all lines their checksum,
	// regardless of which severity chain they took.
	if !strings.Contains(fake.lines["err"][1], "[AUDIT]") {
		t.Errorf("audit error line %q should contain [AUDIT]", fake.lines["err"][1])
	}
	if !strings.Contains(fake.lines["info"][1], "[AUDIT]") {
		t.Errorf("audit info line %q should contain [AUDIT]", fake.lines["info"][1])
	}
	// Lines are formatted "<checksum> [AUDIT] <record>" / "<checksum> <record>",
	// with the checksum covering everything after it except the trailing
	// newline.
	for severity, lines := range fake.lines {
		for _, line := range lines {
			checksum, body, ok := strings.Cut(strings.TrimSuffix(line, "\n"), " ")
			if !ok || checksum != LogLineChecksum(body) {
				t.Errorf("severity %q line %q lacks a valid checksum prefix", severity, line)
			}
		}
	}
}

func TestSeverityHandlerLevelFiltering(t *testing.T) {
	t.Parallel()

	// A severityHandler built at level 3 (errors only) must not emit anything
	// for lower-severity records.
	fake := newFakeSyslog()
	l := &logger{inner: slog.New(&contextHandler{inner: newSeverityHandler(fake, 3)})}
	ctx := context.Background()

	l.Error(ctx, "an error", errors.New("boom"))
	l.Warn(ctx, "a warning")
	l.Info(ctx, "some info")
	l.Debug(ctx, "some detail")

	fake.mu.Lock()
	defer fake.mu.Unlock()

	if len(fake.lines["err"]) != 1 {
		t.Errorf("severity err received %d lines, want 1: %v", len(fake.lines["err"]), fake.lines["err"])
	}
	for _, severity := range []string{"warning", "info", "debug"} {
		if len(fake.lines[severity]) != 0 {
			t.Errorf("severity %q received %d lines, want 0 at config level 3: %v",
				severity, len(fake.lines[severity]), fake.lines[severity])
		}
	}
}
