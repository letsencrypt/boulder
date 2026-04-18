//go:build !integration

package blog

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/core"
)

// stdlibHandler constructs the underlying handler provided by the go
// standard library appropriate to the current environment.
//
// In unit tests, we use the TextHandler for ease of assertion readability.
// In actual production code, we use the JSONHandler.
func stdlibHandler(w io.Writer, opts *slog.HandlerOptions) slog.Handler {
	if testing.Testing() {
		return slog.NewTextHandler(w, opts)
	} else {
		return slog.NewJSONHandler(w, opts)
	}
}

// universalAttrs returns the set of slog.Attrs which should be included in all
// log lines. It returns []any instead of []slog.Attr because slog doesn't have
// a Logger.WithAttr() method.
//
// Because this is used in production, it returns a similar set of attributes
// as syslog would add automatically.
func universalAttrs() []any {
	shortHostname := "unknown"
	datacenter := "unknown"
	hostname, err := os.Hostname()
	if err == nil {
		splits := strings.SplitN(hostname, ".", 3)
		shortHostname = splits[0]
		if len(splits) > 1 {
			datacenter = splits[1]
		}
	}

	return []any{
		slog.String("dc", datacenter),
		slog.String("host", shortHostname),
		slog.String("prog", core.Command()),
		slog.Int("pid", os.Getpid()),
	}
}
