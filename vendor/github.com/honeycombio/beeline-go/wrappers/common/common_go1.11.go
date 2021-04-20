//+build go1.11

package common

import (
	"database/sql"

	"github.com/honeycombio/beeline-go/trace"
	libhoney "github.com/honeycombio/libhoney-go"
)

func addDBStatsToEvent(ev *libhoney.Event, stats sql.DBStats) {
	ev.AddField("db.open_conns", stats.OpenConnections)
	ev.AddField("db.conns_in_use", stats.InUse)
	ev.AddField("db.conns_idle", stats.Idle)
	ev.AddField("db.wait_count", stats.WaitCount)
	ev.AddField("db.wait_duration", stats.WaitDuration)
}

func addDBStatsToSpan(span *trace.Span, stats sql.DBStats) {
	span.AddField("db.open_conns", stats.OpenConnections)
	span.AddField("db.conns_in_use", stats.InUse)
	span.AddField("db.conns_idle", stats.Idle)
	span.AddField("db.wait_count", stats.WaitCount)
	span.AddField("db.wait_duration", stats.WaitDuration)
}
