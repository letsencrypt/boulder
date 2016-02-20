// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package metrics

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
)

// HTTPMonitor stores some server state
type HTTPMonitor struct {
	stats               statsd.Statter
	statsPrefix         string
	handler             http.Handler
	connectionsInFlight int64
}

// NewHTTPMonitor returns a new initialized HTTPMonitor
func NewHTTPMonitor(stats statsd.Statter, handler http.Handler, prefix string) *HTTPMonitor {
	return &HTTPMonitor{
		stats:               stats,
		handler:             handler,
		statsPrefix:         prefix,
		connectionsInFlight: 0,
	}
}

func (h *HTTPMonitor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.stats.Inc(fmt.Sprintf("%s.HTTP.Rate", h.statsPrefix), 1, 1.0)
	inFlight := atomic.AddInt64(&h.connectionsInFlight, 1)
	h.stats.Gauge(fmt.Sprintf("%s.HTTP.OpenConnections", h.statsPrefix), inFlight, 1.0)

	h.handler.ServeHTTP(w, r)

	inFlight = atomic.AddInt64(&h.connectionsInFlight, -1)
	h.stats.Gauge(fmt.Sprintf("%s.HTTP.ConnectionsInFlight", h.statsPrefix), inFlight, 1.0)
}

// FBAdapter provides a facebookgo/stats client interface that sends metrics via
// a StatsD client
type FBAdapter struct {
	stats  statsd.Statter
	prefix string
	clk    clock.Clock
}

// NewFBAdapter returns a new adapter
func NewFBAdapter(stats statsd.Statter, prefix string, clock clock.Clock) FBAdapter {
	return FBAdapter{stats: stats, prefix: prefix, clk: clock}
}

// BumpAvg is essentially statsd.Statter.Gauge
func (fba FBAdapter) BumpAvg(key string, val float64) {
	fba.stats.Gauge(fmt.Sprintf("%s.%s", fba.prefix, key), int64(val), 1.0)
}

// BumpSum is essentially statsd.Statter.Inc (httpdown only ever uses positive
// deltas)
func (fba FBAdapter) BumpSum(key string, val float64) {
	fba.stats.Inc(fmt.Sprintf("%s.%s", fba.prefix, key), int64(val), 1.0)
}

type btHolder struct {
	key     string
	stats   statsd.Statter
	started time.Time
}

func (bth btHolder) End() {
	bth.stats.TimingDuration(bth.key, time.Since(bth.started), 1.0)
}

// BumpTime is essentially a (much better) statsd.Statter.TimingDuration
func (fba FBAdapter) BumpTime(key string) interface {
	End()
} {
	return btHolder{
		key:     fmt.Sprintf("%s.%s", fba.prefix, key),
		started: fba.clk.Now(),
		stats:   fba.stats,
	}
}

// BumpHistogram isn't used by facebookgo/httpdown
func (fba FBAdapter) BumpHistogram(_ string, _ float64) {
	return
}
