// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package metrics

import (
	"fmt"
	"net/http"
	"strings"
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
func NewHTTPMonitor(stats statsd.Statter, handler http.Handler, prefix string) HTTPMonitor {
	return HTTPMonitor{
		stats:               stats,
		handler:             handler,
		statsPrefix:         prefix,
		connectionsInFlight: 0,
	}
}

// Handle wraps handlers and records various metrics about requests to these handlers
// and sends them to StatsD
func (h *HTTPMonitor) Handle() http.Handler {
	return http.HandlerFunc(h.watchAndServe)
}

func (h *HTTPMonitor) watchAndServe(w http.ResponseWriter, r *http.Request) {
	h.stats.Inc(fmt.Sprintf("%s.HTTP.Rate", h.statsPrefix), 1, 1.0)
	inFlight := atomic.AddInt64(&h.connectionsInFlight, 1)
	h.stats.Gauge(fmt.Sprintf("%s.HTTP.OpenConnections", h.statsPrefix), inFlight, 1.0)

	cOpened := time.Now()
	h.handler.ServeHTTP(w, r)
	cClosed := time.Since(cOpened)

	inFlight = atomic.AddInt64(&h.connectionsInFlight, -1)
	h.stats.Gauge(fmt.Sprintf("%s.HTTP.ConnectionsInFlight", h.statsPrefix), inFlight, 1.0)

	endpoint := ""
	// If request fails don't record the endpoint as an attacker could use this to
	// eat up all our memory by just hitting 404s all day
	if w.Header().Get("Content-Type") == "application/problem+json" {
		endpoint = "Failed"
	} else {
		// If r.URL has more than two segments throw the rest away to simplify metrics
		segments := strings.Split(r.URL.Path, "/")
		if len(segments) > 3 {
			segments = segments[:3]
		}
		endpoint = strings.Join(segments, "/")
	}
	h.stats.TimingDuration(fmt.Sprintf("%s.HTTP.ResponseTime.%s", h.statsPrefix, endpoint), cClosed, 1.0)
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
