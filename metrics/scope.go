//go:generate mockgen -package metrics -destination ./mock_statsd.go github.com/cactus/go-statsd-client/statsd Statter

package metrics

import (
	"strings"
	"time"

	"github.com/cactus/go-statsd-client/statsd"
)

// Scope is a stats collector that will prefix the name the stats it
// collects.
type Scope interface {
	NewScope(scopes ...string) Scope
	Scope() string

	Inc(stat string, value int64) error
	Dec(stat string, value int64) error
	Gauge(stat string, value int64) error
	GaugeDelta(stat string, value int64) error
	Timing(stat string, delta int64) error
	TimingDuration(stat string, delta time.Duration) error
	Set(stat string, value string) error
	SetInt(stat string, value int64) error
	Raw(stat string, value string) error
}

// StatsdScope is a Scope that sends data to statsd with a prefix added to the
// stat names.
type StatsdScope struct {
	prefix  string
	statter statsd.Statter
}

var _ Scope = &StatsdScope{}

// NewStatsdScope returns a StatsdScope that prefixes stats it collections with
// the scopes given joined together by periods
func NewStatsdScope(statter statsd.Statter, scopes ...string) *StatsdScope {
	return &StatsdScope{
		prefix:  strings.Join(scopes, ".") + ".",
		statter: statter,
	}
}

// NewNoopScope returns a Scope that won't collect anything
func NewNoopScope() Scope {
	c, _ := statsd.NewNoopClient()
	return NewStatsdScope(c, "noop")
}

// NewScope generates a new Scope prefixed by this Scope's prefix plus the
// prefixes given joined by periods
func (s *StatsdScope) NewScope(scopes ...string) Scope {
	scope := strings.Join(scopes, ".")
	return NewStatsdScope(s.statter, s.prefix+scope)
}

// Scope returns the current string prefix (except for the final period) that
// stats will receive
func (s *StatsdScope) Scope() string {
	return s.prefix[:len(s.prefix)-1]
}

// Inc increments the given stat and adds the Scope's prefix to the name
func (s *StatsdScope) Inc(stat string, value int64) error {
	autoCounter(s.prefix + stat).Add(float64(1))
	return s.statter.Inc(s.prefix+stat, value, 1.0)
}

// Dec decrements the given stat and adds the Scope's prefix to the name
func (s *StatsdScope) Dec(stat string, value int64) error {
	return s.statter.Dec(s.prefix+stat, value, 1.0)
}

// Gauge sends a gauge stat and adds the Scope's prefix to the name
func (s *StatsdScope) Gauge(stat string, value int64) error {
	autoGauge(s.prefix + stat).Set(float64(value))
	return s.statter.Gauge(s.prefix+stat, value, 1.0)
}

// GaugeDelta sends the change in a gauge stat and adds the Scope's prefix to the name
func (s *StatsdScope) GaugeDelta(stat string, value int64) error {
	autoGauge(s.prefix + stat).Add(float64(value))
	return s.statter.GaugeDelta(s.prefix+stat, value, 1.0)
}

// Timing sends a latency stat and adds the Scope's prefix to the name
func (s *StatsdScope) Timing(stat string, delta int64) error {
	autoSummary(s.prefix + stat).Observe(float64(delta))
	return s.statter.Timing(s.prefix+stat, delta, 1.0)
}

// TimingDuration sends a latency stat as a time.Duration and adds the Scope's
// prefix to the name
func (s *StatsdScope) TimingDuration(stat string, delta time.Duration) error {
	autoSummary(s.prefix + stat).Observe(delta.Seconds())
	return s.statter.TimingDuration(s.prefix+stat, delta, 1.0)
}

// Set sets a stat's new value and adds the Scope's prefix to the name
func (s *StatsdScope) Set(stat string, value string) error {
	return s.statter.Set(s.prefix+stat, value, 1.0)
}

// SetInt sets a stat's integer value and adds the Scope's prefix to the name
func (s *StatsdScope) SetInt(stat string, value int64) error {
	autoGauge(s.prefix + stat).Set(float64(value))
	return s.statter.SetInt(s.prefix+stat, value, 1.0)
}

// Raw sends a stat value without interpretation and adds the Scope's prefix to
// the name
func (s *StatsdScope) Raw(stat string, value string) error {
	return s.statter.Raw(s.prefix+stat, value, 1.0)
}
