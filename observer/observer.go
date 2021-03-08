package observer

import (
	"fmt"
	"strconv"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"

	// _ are probes imported to trigger init func
	_ "github.com/letsencrypt/boulder/observer/probers/dns"
	_ "github.com/letsencrypt/boulder/observer/probers/http"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	statMonitors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "obs_monitors",
			Help: "count of configured monitors",
		},
		[]string{"name", "kind", "valid"},
	)
	statObservations = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "obs_observations",
			Help:    "time taken for a monitor to perform a request/query",
			Buckets: metrics.InternetFacingBuckets,
		},
		[]string{"name", "kind", "result"},
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

	// start each monitor
	for _, mon := range o.Monitors {
		if mon.valid {
			go mon.start()
		}

	}
	// run forever
	select {}
}

// New attempts to populate and return an `Observer` object with the
// contents of an `ObsConf`. If the `ObsConf` cannot be validated, an
// error appropriate for end-user consumption is returned
func New(c ObsConf, configPath string) (*Observer, error) {
	// validate the `ObsConf`
	err := c.validate()
	if err != nil {
		return nil, err
	}

	// start monitoring and logging
	p, l := cmd.StatsAndLogging(c.Syslog, c.DebugAddr)
	defer l.AuditPanic()
	l.Info(cmd.VersionString())
	l.Infof("Initializing boulder-observer daemon from config: %s", configPath)
	l.Debugf("Using config: %+v", c)

	errs, ok := c.validateMonConfs()
	for mon, err := range errs {
		l.Errf("monitor %q is invalid: %s", mon, err)
	}

	if len(errs) != 0 {
		l.Errf("%d of %d monitors failed validation", len(errs), len(c.MonConfs))
	} else {
		l.Info("all monitors passed validation")
	}

	// if 0 `MonConfs` passed validation, return error
	if !ok {
		return nil, fmt.Errorf("no valid mons, cannot continue")
	}

	// register metrics
	p.MustRegister(statObservations)
	p.MustRegister(statMonitors)

	// Create a `monitor` for each `MonConf`
	var monitors []*monitor
	for _, m := range c.MonConfs {
		if !m.Valid {
			statMonitors.WithLabelValues(
				"", m.Kind, strconv.FormatBool(m.Valid)).Inc()
		} else {
			monitors = append(
				monitors, &monitor{m.Valid, m.Period.Duration, m.getProber(), l, p})
		}
	}
	return &Observer{l, p, monitors}, nil
}
