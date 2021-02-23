package observer

import (
	"time"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	statTotalMonitors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "obs_monitors",
			Help: "count of configured monitors",
		},
		[]string{"plugin", "name"},
	)
	statTotalErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "obs_errors",
			Help: "count of errors encountered by all monitors",
		},
		[]string{"plugin", "name"},
	)
	statTotalObservations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "obs_oberservations",
			Help: "count of observations performed by all monitors",
		},
		[]string{"plugin", "name"},
	)
)

// Observer acts as the
type Observer struct {
	Timeout  time.Duration
	Logger   blog.Logger
	Metric   prometheus.Registerer
	Monitors []*monitor
}

// Start acts as the supervisor for all monitor goroutines
func (o Observer) Start() {
	runningChan := make(chan bool)

	// register metrics
	o.Metric.MustRegister(statTotalErrors)
	o.Metric.MustRegister(statTotalMonitors)
	o.Metric.MustRegister(statTotalObservations)

	// start each monitor
	for _, mon := range o.Monitors {
		statTotalMonitors.WithLabelValues(mon.pluginIs, mon.name).Inc()
		go mon.start()
	}

	// run forever
	<-runningChan
}

// New initializes new Observer objects
func New(c ObsConf, l blog.Logger, p prometheus.Registerer) *Observer {
	var o Observer
	o.Timeout = time.Duration(c.Timeout * 1000000000)
	o.Logger = l
	o.Metric = p
	for _, monConf := range c.NewMons {
		var mon monitor
		o.Monitors = append(o.Monitors, mon.New(monConf, l, p, c.Timeout))
	}
	return &o
}
