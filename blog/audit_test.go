package blog

import (
	"bytes"
	"testing"
)

func TestAuditWriter(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "empty",
			in:   "",
			want: "[AUDIT] ",
		},
		{
			name: "simple",
			in:   "hello, world",
			want: "[AUDIT] hello, world",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			w := &auditWriter{inner: &buf}
			n, err := w.Write([]byte(tc.in))
			if err != nil {
				t.Fatalf("auditWriter.Write returned error: %s", err)
			}
			if n != len(tc.in) {
				t.Errorf("auditWriter.Write returned n=%d, want %d", n, len(tc.in))
			}
			got := buf.String()
			if got != tc.want {
				t.Errorf("auditWriter wrote %q, want %q", got, tc.want)
			}
		})
	}

	// Each call to Write produces its own [AUDIT]-prefixed line.
	t.Run("multiple writes", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := &auditWriter{inner: &buf}
		for _, line := range []string{"foo", "bar"} {
			n, err := w.Write([]byte(line))
			if err != nil {
				t.Fatalf("auditWriter.Write(%q) returned error: %s", line, err)
			}
			if n != len(line) {
				t.Errorf("auditWriter.Write(%q) returned n=%d, want %d", line, n, len(line))
			}
		}
		want := "[AUDIT] foo[AUDIT] bar"
		got := buf.String()
		if got != want {
			t.Errorf("auditWriter wrote %q, want %q", got, want)
		}
	})
}
