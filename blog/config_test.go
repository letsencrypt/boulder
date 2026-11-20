package blog

import (
	"log/slog"
	"testing"
)

func TestConfigToSlogLevel(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		in   int
		want slog.Level
	}{
		{name: "1 -> Error", in: 1, want: slog.LevelError},
		{name: "2 -> Error", in: 2, want: slog.LevelError},
		{name: "3 -> Error", in: 3, want: slog.LevelError},
		{name: "4 -> Warn", in: 4, want: slog.LevelWarn},
		{name: "5 -> Warn", in: 5, want: slog.LevelWarn},
		{name: "6 -> Info", in: 6, want: slog.LevelInfo},
		{name: "7 -> Debug", in: 7, want: slog.LevelDebug},
		// Unspecified values fall through to Info.
		{name: "0 -> Info (default)", in: 0, want: slog.LevelInfo},
		{name: "-1 -> Info (default)", in: -1, want: slog.LevelInfo},
		{name: "99 -> Info (default)", in: 99, want: slog.LevelInfo},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := configToSlogLevel(tc.in)
			if got != tc.want {
				t.Errorf("configToSlogLevel(%d) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}
