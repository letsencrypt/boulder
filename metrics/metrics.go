// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package metrics

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"

	"github.com/letsencrypt/boulder/rpc"
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

// RPCMonitor stores rpc delivery state
type RPCMonitor struct {
	deliveryTimings map[string]time.Time
	dtMu            *sync.Mutex

	stats statsd.Statter
}

// NewRPCMonitor returns a new initialized RPCMonitor and starts a goroutine
// to cleanup timeouts from the delivery map
func NewRPCMonitor(stats statsd.Statter) RPCMonitor {
	r := RPCMonitor{stats: stats, deliveryTimings: make(map[string]time.Time), dtMu: &sync.Mutex{}}
	go func() {
		c := time.Tick(time.Second * 5)
		for _ = range c {
			if t := r.cleanup(); t > 0 {
				stats.Inc("RPC.Timeouts", t, 1.0)
			}
		}
	}()
	return r
}

func (r *RPCMonitor) size() int {
	r.dtMu.Lock()
	defer r.dtMu.Unlock()
	return len(r.deliveryTimings)
}

func (r *RPCMonitor) get(id string) time.Time {
	r.dtMu.Lock()
	defer r.dtMu.Unlock()
	return r.deliveryTimings[id]
}

func (r *RPCMonitor) add(id string) {
	r.dtMu.Lock()
	defer r.dtMu.Unlock()
	r.deliveryTimings[id] = time.Now()
}

func (r *RPCMonitor) delete(id string) {
	r.dtMu.Lock()
	defer r.dtMu.Unlock()
	delete(r.deliveryTimings, id)
}

func (r *RPCMonitor) cleanup() (removed int64) {
	r.dtMu.Lock()
	defer r.dtMu.Unlock()
	for k, v := range r.deliveryTimings {
		if time.Now().Add(-time.Second * 10).After(v) {
			// If the delivery has been in the map for more than 10 seconds
			// it has timed out, delete it so the map doesn't grow
			// indefinitely.
			delete(r.deliveryTimings, k)
			removed++
		}
	}
	return removed
}

// TimeDelivery takes a single RPC delivery and provides metrics to StatsD about it
func (r *RPCMonitor) TimeDelivery(d amqp.Delivery) {
	// If d is a call add to deliveryTimings and increment openCalls, if it is a
	// response then get time.Since original call from deliveryTiming, send timing metric, and
	// decrement openCalls, in both cases send the gauge RpcCallsWaiting and increment the counter
	// RpcTraffic with the byte length of the RPC body.
	r.stats.Inc("RPC.Traffic", int64(len(d.Body)), 1.0)
	r.stats.Gauge("RPC.CallsWaiting", int64(r.size()), 1.0)

	if d.ReplyTo != "" {
		r.add(fmt.Sprintf("%s:%s", d.CorrelationId, d.ReplyTo))
	} else {
		rpcSent := r.get(fmt.Sprintf("%s:%s", d.CorrelationId, d.RoutingKey))
		if rpcSent != *new(time.Time) {
			respTime := time.Since(rpcSent)
			r.delete(fmt.Sprintf("%s:%s", d.CorrelationId, d.RoutingKey))

			// Check if the call failed
			state := "Success"
			var resp struct {
				Error rpc.RPCError
			}
			json.Unmarshal(d.Body, &resp)
			if resp.Error.Value != "" {
				state = "Error"
			}
			r.stats.Inc(fmt.Sprintf("RPC.Rate.%s", state), 1, 1.0)
			r.stats.TimingDuration(fmt.Sprintf("RPC.ResponseTime.%s.%s", d.Type, state), respTime, 1.0)
		} else {
		}
	}
}
