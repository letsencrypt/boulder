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

	Inc(stat string, value int64) error
	Gauge(stat string, value int64) error
	GaugeDelta(stat string, value int64) error
	Timing(stat string, delta int64) error
	TimingDuration(stat string, delta time.Duration) error
	SetInt(stat string, value int64) error
}

// promScope is a Scope that sends data to Prometheus
type promScope struct {
	*autoRegisterer
	prefix     string
	registerer prometheus.Registerer
}

var _ Scope = &promScope{}

// NewPromScope returns a Scope that sends data to Prometheus
func NewPromScope(registerer prometheus.Registerer, scopes ...string) Scope {
	return &promScope{
		prefix:         strings.Join(scopes, ".") + ".",
		autoRegisterer: newAutoRegisterer(registerer),
	}
}

// NewNoopScope returns a Scope that won't collect anything
func NewNoopScope() Scope {
	return NewPromScope(prometheus.NewRegistry())
}

// NewScope generates a new Scope prefixed by this Scope's prefix plus the
// prefixes given joined by periods
func (s *promScope) NewScope(scopes ...string) Scope {
	scope := strings.Join(scopes, ".")
	return NewPromScope(s.registerer, s.prefix+scope)
}

// Inc increments the given stat and adds the Scope's prefix to the name
func (s *promScope) Inc(stat string, value int64) error {
	s.autoCounter(s.prefix + stat).Add(float64(value))
	return nil
}

// Gauge sends a gauge stat and adds the Scope's prefix to the name
func (s *promScope) Gauge(stat string, value int64) error {
	s.autoGauge(s.prefix + stat).Set(float64(value))
	return nil
}

// GaugeDelta sends the change in a gauge stat and adds the Scope's prefix to the name
func (s *promScope) GaugeDelta(stat string, value int64) error {
	s.autoGauge(s.prefix + stat).Add(float64(value))
	return nil
}

// Timing sends a latency stat and adds the Scope's prefix to the name
func (s *promScope) Timing(stat string, delta int64) error {
	s.autoSummary(s.prefix + stat + "_seconds").Observe(float64(delta))
	return nil
}

// TimingDuration sends a latency stat as a time.Duration and adds the Scope's
// prefix to the name
func (s *promScope) TimingDuration(stat string, delta time.Duration) error {
	s.autoSummary(s.prefix + stat + "_seconds").Observe(delta.Seconds())
	return nil
}

// SetInt sets a stat's integer value and adds the Scope's prefix to the name
func (s *promScope) SetInt(stat string, value int64) error {
	s.autoGauge(s.prefix + stat).Set(float64(value))
	return nil
}
