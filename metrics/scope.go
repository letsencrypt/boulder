package metrics

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Scope is a stats collector that will prefix the name the stats it
// collects.
type Scope interface {
	NewScope(scopes ...string) Scope

	Inc(stat string, value int64)
	Gauge(stat string, value int64)
	GaugeDelta(stat string, value int64)
	Timing(stat string, delta int64)
	TimingDuration(stat string, delta time.Duration)
	SetInt(stat string, value int64)

	MustRegister(...prometheus.Collector)
}

// promScope is a Scope that sends data to Prometheus
type promScope struct {
	*autoRegisterer
	prefix     []string
	registerer prometheus.Registerer
}

var _ Scope = &promScope{}

// NewPromScope returns a Scope that sends data to Prometheus
func NewPromScope(registerer prometheus.Registerer, scopes ...string) Scope {
	return &promScope{
		prefix:         scopes,
		autoRegisterer: newAutoRegisterer(registerer),
		registerer:     registerer,
	}
}

func (s *promScope) MustRegister(collectors ...prometheus.Collector) {
	s.registerer.MustRegister(collectors...)
}

// NewScope generates a new Scope prefixed by this Scope's prefix plus the
// prefixes given joined by periods
func (s *promScope) NewScope(scopes ...string) Scope {
	return &promScope{
		prefix:         append(s.prefix, scopes...),
		autoRegisterer: s.autoRegisterer,
		registerer:     s.registerer,
	}
}

// Inc increments the given stat and adds the Scope's prefix to the name
func (s *promScope) Inc(stat string, value int64) {
	s.autoCounter(s.statName(stat)).Add(float64(value))
}

// Gauge sends a gauge stat and adds the Scope's prefix to the name
func (s *promScope) Gauge(stat string, value int64) {
	s.autoGauge(s.statName(stat)).Set(float64(value))
}

// GaugeDelta sends the change in a gauge stat and adds the Scope's prefix to the name
func (s *promScope) GaugeDelta(stat string, value int64) {
	s.autoGauge(s.statName(stat)).Add(float64(value))
}

// Timing sends a latency stat and adds the Scope's prefix to the name
func (s *promScope) Timing(stat string, delta int64) {
	s.autoSummary(s.statName(stat) + "_seconds").Observe(float64(delta))
}

// TimingDuration sends a latency stat as a time.Duration and adds the Scope's
// prefix to the name
func (s *promScope) TimingDuration(stat string, delta time.Duration) {
	s.autoSummary(s.statName(stat) + "_seconds").Observe(delta.Seconds())
}

// SetInt sets a stat's integer value and adds the Scope's prefix to the name
func (s *promScope) SetInt(stat string, value int64) {
	s.autoGauge(s.statName(stat)).Set(float64(value))
}

// statName construct a name for a stat based on the prefix of this scope, plus
// the provided string.
func (s *promScope) statName(stat string) string {
	if len(s.prefix) > 0 {
		return strings.Join(s.prefix, "_") + "_" + stat
	}
	return stat
}

type noopScope struct{}

// NewNoopScope returns a Scope that won't collect anything
func NewNoopScope() Scope {
	return noopScope{}
}

func (n noopScope) NewScope(scopes ...string) Scope {
	return n
}

func (n noopScope) Inc(stat string, value int64) {
}

func (n noopScope) Gauge(stat string, value int64) {
}

func (n noopScope) GaugeDelta(stat string, value int64) {
}

func (n noopScope) Timing(stat string, delta int64) {
}

func (n noopScope) TimingDuration(stat string, delta time.Duration) {
}

func (n noopScope) SetInt(stat string, value int64) {
}

func (n noopScope) MustRegister(...prometheus.Collector) {
}
