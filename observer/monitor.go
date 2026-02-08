package observer

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/letsencrypt/boulder/blog"
	"github.com/letsencrypt/boulder/observer/probers"
)

type monitor struct {
	period time.Duration
	prober probers.Prober
}

// start spins off a 'Prober' goroutine on an interval of `m.period`
// with a timeout of half `m.period`
func (m monitor) start(ctx context.Context) {
	ticker := time.NewTicker(m.period)
	timeout := m.period / 2
	for {
		go func() {
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			// Attempt to probe the configured target.
			success, dur := m.prober.Probe(ctx)

			// Produce metrics to be scraped by Prometheus.
			histObservations.WithLabelValues(
				m.prober.Name(), m.prober.Kind(), strconv.FormatBool(success),
			).Observe(dur.Seconds())

			// Log the outcome of the probe attempt.
			blog.Info(ctx, "Probe complete",
				slog.String("kind", m.prober.Kind()),
				slog.String("name", m.prober.Name()),
				slog.Bool("success", success),
				slog.Duration("duration", dur),
			)
		}()
		<-ticker.C
	}
}
