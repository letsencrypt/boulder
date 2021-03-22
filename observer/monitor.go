package observer

import (
	"strconv"
	"time"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/observer/probers"
	"github.com/prometheus/client_golang/prometheus"
)

type monitor struct {
	period time.Duration
	prober probers.Prober
	logger blog.Logger
	metric prometheus.Registerer
}

// start spins off a goroutine that attempts to probe for each period
// specified in the monitor config.
func (m monitor) start() {
	go func() {
		for {
			select {
			case <-time.NewTicker(m.period).C:
				// Attempt to probe the configured target.
				success, dur := m.prober.Probe(m.period)
				// Produce metrics to be scraped by Prometheus.
				statObservations.WithLabelValues(
					m.prober.Name(), m.prober.Kind(), strconv.FormatBool(success),
				).Observe(dur.Seconds())
				// Log the outcome of the probe attempt.
				m.logger.Infof(
					"kind=[%s] success=[%v] duration=[%f] name=[%s]",
					m.prober.Kind(), success, dur.Seconds(), m.prober.Name())
			}
		}
	}()
}
