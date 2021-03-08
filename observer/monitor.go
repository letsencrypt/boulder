package observer

import (
	"strconv"
	"time"

	blog "github.com/letsencrypt/boulder/log"
	p "github.com/letsencrypt/boulder/observer/probers"
	"github.com/prometheus/client_golang/prometheus"
)

// monitor contains the parsed, normalized, and validated configuration
// describing a given oberver monitor
type monitor struct {
	valid  bool
	period time.Duration
	prober p.Prober
	logger blog.Logger
	metric prometheus.Registerer
}

// start creates a ticker channel then spins off a prober goroutine for
// each period specified in the monitor config and a timeout inferred
// from that period. This is not perfect, it means that the effective
// deadline for a prober goroutine will be TTL + time-to-schedule, but
// it's close enough for our purposes
func (m monitor) start() *time.Ticker {
	ticker := time.NewTicker(m.period)
	go func() {
		for {
			select {
			case <-ticker.C:
				result, dur := m.prober.Probe(m.period)
				statObservations.WithLabelValues(
					m.prober.Name(), m.prober.Kind(), strconv.FormatBool(result)).
					Observe(dur.Seconds())
				m.logger.Infof(
					"kind=[%s] result=[%v] duration=[%f] name=[%s]",
					m.prober.Kind(), result, dur.Seconds(), m.prober.Name())
			}
		}
	}()
	return ticker
}
