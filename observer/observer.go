package observer

import (
	"strconv"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"

	// _ are probes imported to trigger init func
	_ "github.com/letsencrypt/boulder/observer/probes/dns"
	_ "github.com/letsencrypt/boulder/observer/probes/http"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	statMonitors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "obs_monitors",
			Help: "count of configured monitors",
		},
		[]string{"name", "type", "valid"},
	)
	statObservations = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "obs_observations",
			Help:    "time taken for a monitor to perform a request/query",
			Buckets: metrics.InternetFacingBuckets,
		},
		[]string{"name", "type", "result"},
	)
)

// Observer contains the parsed, normalized, and validated configuration
// describing a collection of monitors and the metrics to be collected
type Observer struct {
	Logger   blog.Logger
	Metric   prometheus.Registerer
	Monitors []*monitor
}

// Start registers global metrics and spins off a goroutine for each of
// the configured monitors
func (o Observer) Start() {
	// register metrics
	o.Metric.MustRegister(statMonitors)
	o.Metric.MustRegister(statObservations)

	// start each monitor
	for _, mon := range o.Monitors {
		if mon.valid {
			// TODO(@beautifulentropy): track and restart unhealthy goroutines
			go mon.start()
		}
		statMonitors.WithLabelValues(
			mon.prober.Name(), mon.prober.Type(), strconv.FormatBool(mon.valid)).Inc()
	}
	// run forever
	select {}
}

// New creates new observer and it's corresponding monitor objects
func New(c ObsConf, l blog.Logger, p prometheus.Registerer) *Observer {
	var monitors []*monitor
	for _, c := range c.MonConfs {
		monitors = append(monitors, &monitor{c.Valid, c.Period.Duration, c.getProber(), l, p})
	}
	return &Observer{l, p, monitors}
}
