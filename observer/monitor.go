package observer

import (
	"context"
	"strconv"
	"time"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/observer/probers"
)

type monitor struct {
	period time.Duration
	prober probers.Prober
}

// start spins off a 'Prober' goroutine on an interval of `m.period`
// with a timeout of half `m.period`
func (m monitor) start(logger blog.Logger) {
	ticker := time.NewTicker(m.period)
	for {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), m.period/2)
			defer cancel()

			// Attempt to probe the configured target.
			start := time.Now()
			success := m.prober.Probe(ctx)
			dur := time.Since(start)

			// Produce metrics to be scraped by Prometheus.
			histObservations.WithLabelValues(
				m.prober.Name(), m.prober.Kind(), strconv.FormatBool(success),
			).Observe(dur.Seconds())

			// Log the outcome of the probe attempt.
			logger.Infof(
				"kind=[%s] success=[%v] duration=[%f] name=[%s]",
				m.prober.Kind(), success, dur.Seconds(), m.prober.Name())
		}()
		<-ticker.C
	}
}
