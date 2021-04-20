// +build !go1.11

package common

import (
	"database/sql"

	"github.com/honeycombio/beeline-go/trace"
	libhoney "github.com/honeycombio/libhoney-go"
)

func addDBStatsToEvent(ev *libhoney.Event, stats sql.DBStats) {
	ev.AddField("db.open_conns", stats.OpenConnections)
}

func addDBStatsToSpan(span *trace.Span, stats sql.DBStats) {
	span.AddField("db.open_conns", stats.OpenConnections)
}
