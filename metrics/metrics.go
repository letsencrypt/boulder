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
)

// HTTPMonitor stores some server state
type HTTPMonitor struct {
	stats           statsd.Statter
	statsPrefix     string
	handler         http.Handler
	openConnections *int64
}

// NewHTTPMonitor returns a new initialized HTTPMonitor
func NewHTTPMonitor(stats statsd.Statter, handler http.Handler, prefix string) HTTPMonitor {
	conns := int64(0)
	return HTTPMonitor{stats: stats, handler: handler, statsPrefix: prefix, openConnections: &conns}
}

// Handle wraps handlers and records various metrics about requests to these handlers
// and sends them to StatsD
func (h *HTTPMonitor) Handle() http.Handler {
	return http.HandlerFunc(h.watchAndServe)
}

func (h *HTTPMonitor) watchAndServe(w http.ResponseWriter, r *http.Request) {
	h.stats.Inc(fmt.Sprintf("%s.HTTP.Rate", h.statsPrefix), 1, 1.0)
	open := atomic.AddInt64(h.openConnections, 1)
	h.stats.Gauge(fmt.Sprintf("%s.HTTP.OpenConnections", h.statsPrefix), open, 1.0)

	cOpened := time.Now()
	h.handler.ServeHTTP(w, r)
	cClosed := time.Since(cOpened)

	open = atomic.AddInt64(h.openConnections, -1)
	h.stats.Gauge(fmt.Sprintf("%s.HTTP.OpenConnections", h.statsPrefix), open, 1.0)

	// Check if request failed
	state := "Success"
	if w.Header().Get("Content-Type") == "application/problem+json" {
		state = "Error"
	}

	// If r.URL has more than two segments throw the rest away to simplify metrics
	segments := strings.Split(r.URL.Path, "/")
	if len(segments) > 3 {
		segments = segments[:3]
	}
	endpoint := strings.Join(segments, "/")

	h.stats.TimingDuration(fmt.Sprintf("%s.HTTP.ResponseTime.%s.%s", h.statsPrefix, endpoint, state), cClosed, 1.0)
}
