package blog

import (
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestContextWith(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		ctxFn    func(context.Context) context.Context
		wantKeys []string
		wantLog  []string
	}{
		{
			name:  "empty",
			ctxFn: func(ctx context.Context) context.Context { return ctx },
		},
		{
			name: "single layer",
			ctxFn: func(ctx context.Context) context.Context {
				return ContextWith(ctx, slog.String("k1", "v1"), slog.Int("k2", 2))
			},
			wantKeys: []string{"k1", "k2"},
			wantLog:  []string{"k1=v1", "k2=2"},
		},
		{
			name: "multi-layer",
			ctxFn: func(ctx context.Context) context.Context {
				// ContextWith should append to any existing attrs, not replace them.
				ctx = ContextWith(ctx, slog.String("k1", "v1"))
				ctx = ContextWith(ctx, slog.String("k2", "v2"))
				ctx = ContextWith(ctx, slog.String("k3", "v3"))
				return ctx
			},
			wantKeys: []string{"k1", "k2", "k3"},
			wantLog:  []string{"k1=v1", "k2=v2", "k3=v3"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := tc.ctxFn(t.Context())

			attrs := fromContext(ctx)
			if len(attrs) != len(tc.wantKeys) {
				t.Fatalf("fromContext returned %d attrs, want %d", len(attrs), len(tc.wantKeys))
			}
			for i, want := range tc.wantKeys {
				if attrs[i].Key != want {
					t.Errorf("attrs[%d].Key = %q, want %q", i, attrs[i].Key, want)
				}
			}

			l := NewMock()
			l.Info(ctx, "hello")
			got := l.GetAll()
			if len(got) != 1 {
				t.Fatalf("got %d log lines, want 1: %v", len(got), got)
			}
			for _, want := range tc.wantLog {
				if !strings.Contains(got[0], want) {
					t.Errorf("log line %q does not contain %q", got[0], want)
				}
			}
		})
	}
}
