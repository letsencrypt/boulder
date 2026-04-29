package blog

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	t.Parallel()

	// Both levels suppressed should return an error.
	_, err := New(Config{StdoutLevel: -1, SyslogLevel: -1})
	if err == nil {
		t.Errorf("New with both levels suppressed should error, got nil")
	}

	// An stdout-only logger should be constructable.
	l, err := New(Config{StdoutLevel: 6, SyslogLevel: -1})
	if err != nil {
		t.Fatalf("New with stdout enabled should succeed, got: %s", err)
	}
	if l == nil {
		t.Errorf("New should return a non-nil logger")
	}
}

func TestLoggerMethods(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		logFn    func(l Logger)
		wantMsg  string
		wantLvl  string
		wantErr  string
		wantAttr string
		audit    bool
	}{
		{
			name:    "Info",
			logFn:   func(l Logger) { l.Info(context.Background(), "hi there") },
			wantMsg: `msg="hi there"`,
			wantLvl: "level=INFO",
		},
		{
			name:    "Debug",
			logFn:   func(l Logger) { l.Debug(context.Background(), "debug me") },
			wantMsg: `msg="debug me"`,
			wantLvl: "level=DEBUG",
		},
		{
			name:    "Warn",
			logFn:   func(l Logger) { l.Warn(context.Background(), "careful now") },
			wantMsg: `msg="careful now"`,
			wantLvl: "level=WARN",
		},
		{
			name:    "Error",
			logFn:   func(l Logger) { l.Error(context.Background(), "oh no", errors.New("boom")) },
			wantMsg: `msg="oh no"`,
			wantLvl: "level=ERROR",
			wantErr: `error=boom`,
		},
		{
			name:    "AuditInfo",
			logFn:   func(l Logger) { l.AuditInfo(context.Background(), "important thing") },
			wantMsg: `msg="important thing"`,
			wantLvl: "level=INFO",
			audit:   true,
		},
		{
			name:    "AuditError",
			logFn:   func(l Logger) { l.AuditError(context.Background(), "audit err", errors.New("bad")) },
			wantMsg: `msg="audit err"`,
			wantLvl: "level=ERROR",
			wantErr: `error=bad`,
			audit:   true,
		},
		{
			name: "Info with attrs",
			logFn: func(l Logger) {
				l.Info(context.Background(), "with attrs", slog.String("foo", "bar"), slog.Int("n", 7))
			},
			wantMsg:  `msg="with attrs"`,
			wantLvl:  "level=INFO",
			wantAttr: `foo=bar n=7`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l := NewMock()
			tc.logFn(l)

			got := l.GetAll()
			if len(got) != 1 {
				t.Fatalf("got %d log lines, want 1: %v", len(got), got)
			}
			line := got[0]

			if !strings.Contains(line, tc.wantLvl) {
				t.Errorf("log line %q does not contain %q", line, tc.wantLvl)
			}
			if !strings.Contains(line, tc.wantMsg) {
				t.Errorf("log line %q does not contain %q", line, tc.wantMsg)
			}
			if tc.wantErr != "" && !strings.Contains(line, tc.wantErr) {
				t.Errorf("log line %q does not contain %q", line, tc.wantErr)
			}
			if tc.wantAttr != "" && !strings.Contains(line, tc.wantAttr) {
				t.Errorf("log line %q does not contain %q", line, tc.wantAttr)
			}
			if tc.audit && !strings.Contains(line, "[AUDIT]") {
				t.Errorf("expected audit log line %q to contain [AUDIT]", line)
			}
			if !tc.audit && strings.Contains(line, "[AUDIT]") {
				t.Errorf("non-audit log line %q should not contain [AUDIT]", line)
			}
		})
	}
}

func TestLoggerIncludesContextAttrs(t *testing.T) {
	t.Parallel()

	l := NewMock()
	ctx := ContextWith(context.Background(), slog.String("request", "abc123"))
	l.Info(ctx, "served", slog.Int("code", 200))

	got := l.GetAll()
	if len(got) != 1 {
		t.Fatalf("got %d log lines, want 1: %v", len(got), got)
	}
	for _, want := range []string{"request=abc123", "code=200", "msg=served"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("log line %q does not contain %q", got[0], want)
		}
	}
}

func TestAuditAttrNotEmitted(t *testing.T) {
	t.Parallel()

	// The audit=true attr is an internal marker and should not appear in the
	// resulting output, even though it causes the [AUDIT] prefix to be added.
	l := NewMock()
	l.AuditInfo(context.Background(), "hello")

	got := l.GetAll()
	if len(got) != 1 {
		t.Fatalf("got %d log lines, want 1: %v", len(got), got)
	}
	if !strings.Contains(got[0], "[AUDIT]") {
		t.Errorf("audit log line %q should contain [AUDIT]", got[0])
	}
	if strings.Contains(got[0], "audit=true") {
		t.Errorf("log line %q should not contain audit=true marker", got[0])
	}
}

func TestLoggerChecksum(t *testing.T) {
	t.Parallel()

	// Every log line emitted by a blog.Logger is prefixed with a space-separated
	// base64-encoded CRC32 of the remaining line contents.
	l := NewMock()
	l.Info(context.Background(), "hello")

	got := l.GetAll()
	if len(got) != 1 {
		t.Fatalf("got %d log lines, want 1: %v", len(got), got)
	}

	parts := strings.SplitN(got[0], " ", 2)
	if len(parts) != 2 {
		t.Fatalf("expected log line to have a space-separated checksum prefix, got %q", got[0])
	}
	// The trailing newline is a line terminator, not part of the line, so
	// strip it before computing the expected checksum.
	body := strings.TrimSuffix(parts[1], "\n")
	want := LogLineChecksum(body)
	if parts[0] != want {
		t.Errorf("checksum prefix %q does not match LogLineChecksum of remainder %q", parts[0], want)
	}
}
