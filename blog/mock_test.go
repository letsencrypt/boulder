package blog

import (
	"strings"
	"testing"
)

func TestMockGetAll(t *testing.T) {
	t.Parallel()

	l := NewMock()
	got := l.GetAll()
	if len(got) != 0 {
		t.Errorf("fresh mock has %d log lines, want 0", len(got))
	}

	l.Info(t.Context(), "first")
	l.Info(t.Context(), "second")
	l.Info(t.Context(), "third")

	got = l.GetAll()
	if len(got) != 3 {
		t.Fatalf("got %d log lines, want 3: %v", len(got), got)
	}
	for i, want := range []string{"first", "second", "third"} {
		if !strings.Contains(got[i], want) {
			t.Errorf("log line %d %q does not contain %q", i, got[i], want)
		}
	}
}

func TestMockGetAllMatching(t *testing.T) {
	t.Parallel()

	l := NewMock()
	l.Info(t.Context(), "apple pie")
	l.Info(t.Context(), "apple tart")
	l.Info(t.Context(), "banana bread")

	apples := l.GetAllMatching("apple")
	if len(apples) != 2 {
		t.Errorf("GetAllMatching(%q) returned %d lines, want 2", "apple", len(apples))
	}

	bananas := l.GetAllMatching("banana")
	if len(bananas) != 1 {
		t.Errorf("GetAllMatching(%q) returned %d lines, want 1", "banana", len(bananas))
	}

	cherries := l.GetAllMatching("cherry")
	if len(cherries) != 0 {
		t.Errorf("GetAllMatching(%q) returned %d lines, want 0", "cherry", len(cherries))
	}

	// Regex metacharacters should work.
	bread := l.GetAllMatching("bread|tart")
	if len(bread) != 2 {
		t.Errorf("GetAllMatching(%q) returned %d lines, want 2", "bread|tart", len(bread))
	}
}

func TestMockExpectMatch(t *testing.T) {
	t.Parallel()

	l := NewMock()
	l.Info(t.Context(), "hello world")

	err := l.ExpectMatch("hello")
	if err != nil {
		t.Errorf("ExpectMatch(%q) returned unexpected error: %s", "hello", err)
	}

	err = l.ExpectMatch("goodbye")
	if err == nil {
		t.Errorf("ExpectMatch(%q) should have returned an error, got nil", "goodbye")
	}
}

func TestMockClear(t *testing.T) {
	t.Parallel()

	l := NewMock()
	l.Info(t.Context(), "before")
	got := l.GetAll()
	if len(got) != 1 {
		t.Fatalf("got %d log lines, want 1", len(got))
	}

	l.Clear()
	got = l.GetAll()
	if len(got) != 0 {
		t.Errorf("after Clear, got %d log lines, want 0", len(got))
	}

	l.Info(t.Context(), "after")
	got = l.GetAll()
	if len(got) != 1 {
		t.Fatalf("got %d log lines, want 1: %v", len(got), got)
	}
	if !strings.Contains(got[0], "after") {
		t.Errorf("log line %q does not contain %q", got[0], "after")
	}
}
