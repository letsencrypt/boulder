package metrics

import (
	"fmt"
	"os"
	"time"

	"github.com/cactus/go-statsd-client/statsd"
)

// Statter implements the statsd.Statter interface but
// appends the name of the host the process is running on
// to the end of every stat name
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
	suffix := fmt.Sprintf(".%s", host)
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
