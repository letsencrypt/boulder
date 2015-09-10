// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package metrics

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
)

// HTTPMonitor stores some server state
type HTTPMonitor struct {
	stats               statsd.Statter
	statsPrefix         string
	handler             http.Handler
	connectionsInFlight int64
	openConnections     int64
}

// NewHTTPMonitor returns a new initialized HTTPMonitor
func NewHTTPMonitor(stats statsd.Statter, handler http.Handler, prefix string) HTTPMonitor {
	return HTTPMonitor{
		stats:               stats,
		handler:             handler,
		statsPrefix:         prefix,
		connectionsInFlight: 0,
		openConnections:     0,
	}
}

// ConnectionMonitor provides states on open connection state
func (h *HTTPMonitor) ConnectionMonitor(_ net.Conn, state http.ConnState) {
	var open int64
	switch state {
	case http.StateNew:
		open = atomic.AddInt64(&h.openConnections, 1)
	case http.StateHijacked:
		fallthrough
	case http.StateClosed:
		open = atomic.AddInt64(&h.openConnections, -1)
	default:
		return
	}
	h.stats.Gauge(fmt.Sprintf("%s.HTTP.OpenConnections", h.statsPrefix), open, 1.0)
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

// RPCMonitor stores rpc delivery state
type RPCMonitor struct {
	deliveryTimings map[string]time.Time
	dtMu            *sync.RWMutex

	stats statsd.Statter
	clock clock.Clock
}
