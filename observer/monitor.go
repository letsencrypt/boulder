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
func (m monitor) start(logger blog.Logger) {
	ticker := time.NewTicker(m.period)
	for {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), m.period/2)
			defer cancel()

			ctx = blog.ContextWith(ctx,
				slog.String("kind", m.prober.Kind()),
				slog.String("name", m.prober.Name()),
			)

			// Attempt to probe the configured target.
			start := time.Now()
			err := m.prober.Probe(ctx)
			dur := time.Since(start)

			// Produce metrics to be scraped by Prometheus.
			histObservations.WithLabelValues(
				m.prober.Name(), m.prober.Kind(), strconv.FormatBool(err == nil),
			).Observe(dur.Seconds())

			// Log the outcome of the probe attempt.
			if err != nil {
				logger.Error(ctx, "Probe complete", err,
					slog.Bool("success", false),
					slog.Duration("duration", dur),
				)
			} else {
				logger.Info(ctx, "Probe complete",
					slog.Bool("success", true),
					slog.Duration("duration", dur),
				)
			}
		}()
		<-ticker.C
	}
}
