package metrics

import (
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/cactus/go-statsd-client/statsd"
	"github.com/jmhodges/clock"
)

// HTTPMonitor stores some server state
type HTTPMonitor struct {
	stats               Scope
	handler             http.Handler
	connectionsInFlight int64
}

// NewHTTPMonitor returns a new initialized HTTPMonitor
func NewHTTPMonitor(stats Scope, handler http.Handler) *HTTPMonitor {
	return &HTTPMonitor{
		stats:               stats,
		handler:             handler,
		connectionsInFlight: 0,
	}
}

func (h *HTTPMonitor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.stats.Inc("HTTP.Rate", 1)
	inFlight := atomic.AddInt64(&h.connectionsInFlight, 1)
	h.stats.Gauge("HTTP.OpenConnections", inFlight)

	h.handler.ServeHTTP(w, r)

	inFlight = atomic.AddInt64(&h.connectionsInFlight, -1)
	h.stats.Gauge("HTTP.ConnectionsInFlight", inFlight)
}

// FBAdapter provides a facebookgo/stats client interface that sends metrics via
// a StatsD client
type FBAdapter struct {
	stats Scope
	clk   clock.Clock
}

// NewFBAdapter returns a new adapter
func NewFBAdapter(stats Scope, clock clock.Clock) FBAdapter {
	return FBAdapter{stats: stats, clk: clock}
}

// BumpAvg is essentially statsd.Statter.Gauge
func (fba FBAdapter) BumpAvg(key string, val float64) {
	fba.stats.Gauge(key, int64(val))
}

// BumpSum is essentially statsd.Statter.Inc (httpdown only ever uses positive
// deltas)
func (fba FBAdapter) BumpSum(key string, val float64) {
	fba.stats.Inc(key, int64(val))
}

type btHolder struct {
	key     string
	stats   Scope
	started time.Time
}

func (bth btHolder) End() {
	bth.stats.TimingDuration(bth.key, time.Since(bth.started))
}

// BumpTime is essentially a (much better) statsd.Statter.TimingDuration
func (fba FBAdapter) BumpTime(key string) interface {
	End()
} {
	return btHolder{
		key:     key,
		started: fba.clk.Now(),
		stats:   fba.stats,
	}
}

// BumpHistogram isn't used by facebookgo/httpdown
func (fba FBAdapter) BumpHistogram(_ string, _ float64) {
	return
}

// Statter implements the statsd.Statter interface but
// appends the name of the host the process is running on
// and its PID to the end of every stat name
type Statter struct {
	suffix string
	s      statsd.Statter
}

// NewStatter returns a new statsd.Client wrapper
func NewStatter(addr, prefix string) (Statter, error) {
	host, err := os.Hostname()
	if err != nil {
		return Statter{}, err
	}
	suffix := fmt.Sprintf(".%s.%d", host, os.Getpid())
	s, err := statsd.NewClient(addr, prefix)
	if err != nil {
		return Statter{}, err
	}
	return Statter{suffix, s}, nil
}

// Inc wraps statsd.Client.Inc
func (s Statter) Inc(n string, v int64, r float32) error {
	return s.s.Inc(n+s.suffix, v, r)
}

// Dec wraps statsd.Client.Dec
func (s Statter) Dec(n string, v int64, r float32) error {
	return s.s.Dec(n+s.suffix, v, r)
}

// Gauge wraps statsd.Client.Gauge
func (s Statter) Gauge(n string, v int64, r float32) error {
	return s.s.Gauge(n+s.suffix, v, r)
}

// GaugeDelta wraps statsd.Client.GaugeDelta
func (s Statter) GaugeDelta(n string, v int64, r float32) error {
	return s.s.GaugeDelta(n+s.suffix, v, r)
}

// Timing wraps statsd.Client.Timing
func (s Statter) Timing(n string, v int64, r float32) error {
	return s.s.Timing(n+s.suffix, v, r)
}

// TimingDuration wraps statsd.Client.TimingDuration
func (s Statter) TimingDuration(n string, v time.Duration, r float32) error {
	return s.s.TimingDuration(n+s.suffix, v, r)
}

// Set wraps statsd.Client.Set
func (s Statter) Set(n string, v string, r float32) error {
	return s.s.Set(n+s.suffix, v, r)
}

// SetInt wraps statsd.Client.SetInt
func (s Statter) SetInt(n string, v int64, r float32) error {
	return s.s.SetInt(n+s.suffix, v, r)
}

// Raw wraps statsd.Client.Raw
func (s Statter) Raw(n string, v string, r float32) error {
	return s.s.Raw(n+s.suffix, v, r)
}

// SetPrefix wraps statsd.Client.SetPrefix
func (s Statter) SetPrefix(p string) {
	s.s.SetPrefix(p)
}

// Close wraps statsd.Client.Close
func (s Statter) Close() error {
	return s.s.Close()
}
