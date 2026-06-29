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

func TestSiblingContextIsolation(t *testing.T) {
	t.Parallel()

	// Build a parent whose attrs slice has spare capacity. Without a defensive
	// copy in ContextWith, two sibling appends share this backing array and
	// trample each other's writes.
	parentAttrs := make([]slog.Attr, 0, 4)
	parentAttrs = append(parentAttrs,
		slog.String("a", "1"),
		slog.String("b", "2"),
		slog.String("c", "3"),
	)
	parent := context.WithValue(t.Context(), sloggerCtxKey, parentAttrs)

	child1 := ContextWith(parent, slog.String("child", "one"))
	child2 := ContextWith(parent, slog.String("child", "two"))

	attrs1 := fromContext(child1)
	last1 := attrs1[len(attrs1)-1].Value.String()
	if last1 != "one" {
		t.Errorf("child1's appended attr = %q, want %q (sibling overwrote it)", last1, "one")
	}
	attrs2 := fromContext(child2)
	last2 := attrs2[len(attrs2)-1].Value.String()
	if last2 != "two" {
		t.Errorf("child2's appended attr = %q, want %q", last2, "two")
	}

	l := NewMock()
	l.Info(child1, "from child1")
	l.Info(child2, "from child2")
	got := l.GetAll()
	if len(got) != 2 {
		t.Fatalf("got %d log lines, want 2: %v", len(got), got)
	}
	if !strings.Contains(got[0], "child=one") {
		t.Errorf("log line for child1 %q should contain child=one", got[0])
	}
	if !strings.Contains(got[1], "child=two") {
		t.Errorf("log line for child2 %q should contain child=two", got[1])
	}
}
