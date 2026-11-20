package blog

import (
	"bytes"
	"testing"
)

func TestLogLineChecksum(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		line string
		want string
	}{
		{
			name: "empty",
			line: "",
			// CRC32 of the empty string is 0.
			want: "AAAAAA",
		},
		{
			name: "simple",
			line: "hello, world",
			// Deterministic base64url(CRC32("hello, world")).
			want: "OnKr_w",
		},
		{
			name: "newline",
			line: "hello, world\n",
			// LogLineChecksum hashes every byte, so the trailing newline changes it.
			want: "U3Qk9A",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := LogLineChecksum(tc.line)
			if got != tc.want {
				t.Errorf("LogLineChecksum(%q) = %q, want %q", tc.line, got, tc.want)
			}
			// Checksum should be deterministic across repeated calls.
			if again := LogLineChecksum(tc.line); again != got {
				t.Errorf("LogLineChecksum(%q) not deterministic: got %q then %q", tc.line, got, again)
			}
		})
	}

	// Different inputs produce different checksums.
	if LogLineChecksum("foo") == LogLineChecksum("bar") {
		t.Errorf("LogLineChecksum(%q) and LogLineChecksum(%q) should differ", "foo", "bar")
	}
}

func TestChecksumWriter(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "empty",
			in:   "",
			want: "AAAAAA ",
		},
		{
			name: "simple",
			in:   "hello, world",
			want: "OnKr_w hello, world",
		},
		{
			name: "newline",
			in:   "hello, world\n",
			// The checksumWriter knows that trailing newlines are actually line
			// terminators, not part of the line itself, so it discards them before
			// computing the checksum. Therefore the checksum should be the same.
			want: "OnKr_w hello, world\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			w := newChecksumWriter(&buf)
			n, err := w.Write([]byte(tc.in))
			if err != nil {
				t.Fatalf("checksumWriter.Write returned error: %s", err)
			}
			if n != len(tc.in) {
				t.Errorf("checksumWriter.Write returned n=%d, want %d", n, len(tc.in))
			}
			if got := buf.String(); got != tc.want {
				t.Errorf("checksumWriter wrote %q, want %q", got, tc.want)
			}
		})
	}

	// Each call to Write produces its own checksum-prefixed line.
	t.Run("multiple writes", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		w := newChecksumWriter(&buf)
		for _, line := range []string{"foo", "bar"} {
			n, err := w.Write([]byte(line))
			if err != nil {
				t.Fatalf("checksumWriter.Write(%q) returned error: %s", line, err)
			}
			if n != len(line) {
				t.Errorf("checksumWriter.Write(%q) returned n=%d, want %d", line, n, len(line))
			}
		}
		want := LogLineChecksum("foo") + " foo" + LogLineChecksum("bar") + " bar"
		if got := buf.String(); got != want {
			t.Errorf("checksumWriter wrote %q, want %q", got, want)
		}
	})
}
