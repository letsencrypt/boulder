package observer

import (
	"context"
	"math/rand/v2"
	"strconv"
	"time"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/observer/probers"
)

type monitor struct {
	period time.Duration
	prober probers.Prober
}

// start spins off a 'Prober' goroutine approximately once per `m.period`,
// with a timeout of half `m.period`. The probe attempts start after a random
// delay and have 20% jitter around the configured period, to prevent many
// monitors with the same period from all waking up at the same time.
func (m monitor) start(ctx context.Context, logger blog.Logger) {
	// Wait a random duration of at most one period before the first probe,
	// so that monitors don't all fire at once when the process starts.
	select {
	case <-ctx.Done():
		return
	case <-time.After(rand.N(m.period)):
	}

	for {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), m.period/2)
			defer cancel()

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
				logger.Errf("kind=[%s] success=[%t] duration=[%f] name=[%s] error=[%s]",
					m.prober.Kind(), err == nil, dur.Seconds(), m.prober.Name(), err)
			} else {
				logger.Infof("kind=[%s] success=[%t] duration=[%f] name=[%s]",
					m.prober.Kind(), err == nil, dur.Seconds(), m.prober.Name())
			}
		}()

		// This jitter is equivalent to 1 +/- 0.2*rand.Float64().
		jitter := 0.8 + 0.4*rand.Float64()
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(float64(m.period) * jitter)):
		}
	}
}
