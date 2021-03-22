package observer

import (
	"strconv"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"

	_ "github.com/letsencrypt/boulder/observer/probers/dns"
	_ "github.com/letsencrypt/boulder/observer/probers/http"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	statMonitors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "obs_monitors",
			Help: "details of each configured monitor",
		},
		[]string{"name", "kind", "valid"},
	)
	statObservations = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "obs_observations",
			Help:    "details of each probe attempt",
			Buckets: []float64{.001, .002, .005, .01, .05, .1, .5, 1, 2, 5, 10},
		},
		[]string{"name", "kind", "success"},
	)
)

// Observer contains the parsed, normalized, and validated configuration
// describing a collection of monitors and the metrics to be collected.
type Observer struct {
	Logger   blog.Logger
	Metric   prometheus.Registerer
	Monitors []*monitor
}

// Start spins off a goroutine for each monitor and then runs forever.
func (o Observer) Start() {
	for _, mon := range o.Monitors {
		go mon.start()
	}
	select {}
}

// New attempts to populate an `Observer` object from the contents of an
// `ObsConf`. If the `ObsConf` cannot be validated, an error appropriate
// for end-user consumption is returned.
func New(c ObsConf, configPath string) (*Observer, error) {
	// Validate the `ObsConf`.
	err := c.validate()
	if err != nil {
		return nil, err
	}

	// Start monitoring and logging.
	metrics, logger := cmd.StatsAndLogging(c.Syslog, c.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())
	logger.Infof("Initializing boulder-observer daemon from config: %s", configPath)
	logger.Debugf("Using config: %+v", c)

	errs, err := c.validateMonConfs()
	if err != nil {
		return nil, err
	}

	defer func() {
		if len(errs) != 0 {
			logger.Errf("%d of %d monitors failed validation", len(errs), len(c.MonConfs))
			for _, err := range errs {
				logger.Errf("%s", err)
			}
		} else {
			logger.Info("all monitors passed validation")
		}
	}()

	metrics.MustRegister(statObservations)
	metrics.MustRegister(statMonitors)

	var monitors []*monitor
	for _, m := range c.MonConfs {
		err := m.validate()
		if err != nil {
			statMonitors.WithLabelValues(
				"", m.Kind, strconv.FormatBool(false)).Inc()
		} else {
			monitors = append(
				monitors, &monitor{m.Period.Duration, m.makeProber(), logger, metrics})
		}
	}
	return &Observer{logger, metrics, monitors}, nil
}
