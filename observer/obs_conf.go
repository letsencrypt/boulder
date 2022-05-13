package observer

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/letsencrypt/boulder/cmd"
)

var (
	countMonitors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "obs_monitors",
			Help: "details of each configured monitor",
		},
		[]string{"kind", "valid"},
	)
	histObservations *prometheus.HistogramVec
)

// ObsConf is exported to receive YAML configuration.
type ObsConf struct {
	DebugAddr string           `yaml:"debugaddr"`
	Buckets   []float64        `yaml:"buckets"`
	Syslog    cmd.SyslogConfig `yaml:"syslog"`
	MonConfs  []*MonConf       `yaml:"monitors"`
}

// validateSyslog ensures the the `Syslog` field received by `ObsConf`
// contains valid log levels.
func (c *ObsConf) validateSyslog() error {
	syslog, stdout := c.Syslog.SyslogLevel, c.Syslog.StdoutLevel
	if stdout < 0 || stdout > 7 || syslog < 0 || syslog > 7 {
		return fmt.Errorf(
			"invalid 'syslog', '%+v', valid log levels are 0-7", c.Syslog)
	}
	return nil
}

// validateDebugAddr ensures the `debugAddr` received by `ObsConf` is
// properly formatted and a valid port.
func (c *ObsConf) validateDebugAddr() error {
	_, p, err := net.SplitHostPort(c.DebugAddr)
	if err != nil {
		return fmt.Errorf(
			"invalid 'debugaddr', %q, not expected format", c.DebugAddr)
	}
	port, _ := strconv.Atoi(p)
	if port <= 0 || port > 65535 {
		return fmt.Errorf(
			"invalid 'debugaddr','%d' is not a valid port", port)
	}
	return nil
}

func (c *ObsConf) makeMonitors() ([]*monitor, []error, error) {
	var errs []error
	var monitors []*monitor
	for e, m := range c.MonConfs {
		entry := strconv.Itoa(e + 1)
		monitor, err := m.makeMonitor()
		if err != nil {
			// append validation error to errs
			errs = append(
				errs, fmt.Errorf(
					"'monitors' entry #%s couldn't be validated: %v", entry, err))

			// increment metrics
			countMonitors.WithLabelValues(m.Kind, "false").Inc()
		} else {
			// append monitor to monitors
			monitors = append(monitors, monitor)

			// increment metrics
			countMonitors.WithLabelValues(m.Kind, "true").Inc()
		}
	}
	if len(c.MonConfs) == len(errs) {
		return nil, errs, errors.New("no valid monitors, cannot continue")
	}
	return monitors, errs, nil
}

// MakeObserver constructs an `Observer` object from the contents of the
// bound `ObsConf`. If the `ObsConf` cannot be validated, an error
// appropriate for end-user consumption is returned instead.
func (c *ObsConf) MakeObserver() (*Observer, error) {
	err := c.validateSyslog()
	if err != nil {
		return nil, err
	}

	err = c.validateDebugAddr()
	if err != nil {
		return nil, err
	}

	if len(c.MonConfs) == 0 {
		return nil, errors.New("no monitors provided")
	}

	if len(c.Buckets) == 0 {
		return nil, errors.New("no histogram buckets provided")
	}

	// Start monitoring and logging.
	metrics, logger := cmd.StatsAndLogging(c.Syslog, c.DebugAddr)
	histObservations = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "obs_observations",
			Help:    "details of each probe attempt",
			Buckets: c.Buckets,
		}, []string{"name", "kind", "success"})
	metrics.MustRegister(countMonitors)
	metrics.MustRegister(histObservations)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())
	logger.Infof("Initializing boulder-observer daemon")
	logger.Debugf("Using config: %+v", c)

	monitors, errs, err := c.makeMonitors()
	if len(errs) != 0 {
		logger.Errf("%d of %d monitors failed validation", len(errs), len(c.MonConfs))
		for _, err := range errs {
			logger.Errf("%s", err)
		}
	} else {
		logger.Info("all monitors passed validation")
	}
	if err != nil {
		return nil, err
	}
	return &Observer{logger, monitors}, nil
}
