package sa

import (
	"database/sql"
	"time"

	"github.com/letsencrypt/boulder/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/go-gorp/gorp.v2"
)

// dbMetrics is a struct holding prometheus stats related to the dbMap. Each of
// the prometheus stats corresponds to a field of sql.DBStats.
type dbMetrics struct {
	dbMap              *gorp.DbMap
	maxOpenConnections prometheus.Gauge
	openConnections    prometheus.Gauge
	inUse              prometheus.Gauge
	idle               prometheus.Gauge
	waitCount          prometheus.Counter
	waitDuration       prometheus.Histogram
	maxIdleClosed      prometheus.Counter
	maxLifetimeClosed  prometheus.Counter
}

// InitDBMetrics will register prometheus stats for the provided dbMap under the
// given metrics.Scope. Every 1 second in a separate go routine the prometheus
// stats will be updated based on the gorp dbMap's inner sql.DBMap's DBStats
// structure values.
func InitDBMetrics(dbMap *gorp.DbMap, scope metrics.Scope) {
	// Create a dbMetrics instance and register prometheus metrics
	dbm := newDbMetrics(dbMap, scope)

	// Start the metric reporting goroutine to update the metrics periodically.
	go dbm.reportDBMetrics()
}

// newDbMetrics constructs a dbMetrics instance by registering prometheus stats.
func newDbMetrics(dbMap *gorp.DbMap, scope metrics.Scope) *dbMetrics {
	maxOpenConns := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "max_open_connections",
		Help: "Maximum number of DB connections allowed.",
	})
	scope.MustRegister(maxOpenConns)

	openConns := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "open_connections",
		Help: "Number of established DB connections (in-use and idle).",
	})
	scope.MustRegister(openConns)

	inUse := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "inuse",
		Help: "Number of DB connections currently in use.",
	})
	scope.MustRegister(inUse)

	idle := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "idle",
		Help: "Number of idle DB connections.",
	})
	scope.MustRegister(idle)

	waitCount := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "wait_count",
		Help: "Total number of DB connections waited for.",
	})
	scope.MustRegister(waitCount)

	waitDuration := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "wait_duration",
		Help: "The total time blocked waiting for a new connection.",
	})
	scope.MustRegister(waitDuration)

	maxIdleClosed := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "max_idle_closed",
		Help: "Total number of connections closed due to SetMaxIdleConns.",
	})
	scope.MustRegister(maxIdleClosed)

	maxLifetimeClosed := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "max_lifetime_closed",
		Help: "Total number of connections closed due to SetConnMaxLifetime.",
	})
	scope.MustRegister(maxLifetimeClosed)

	// Construct a dbMetrics instance with all of the registered metrics and the
	// gorp DBMap
	return &dbMetrics{
		dbMap:              dbMap,
		maxOpenConnections: maxOpenConns,
		openConnections:    openConns,
		inUse:              inUse,
		idle:               idle,
		waitCount:          waitCount,
		waitDuration:       waitDuration,
		maxIdleClosed:      maxIdleClosed,
		maxLifetimeClosed:  maxLifetimeClosed,
	}
}

// updateFrom updates the dbMetrics prometheus stats based on the provided
// sql.DBStats object.
func (dbm *dbMetrics) updateFrom(dbStats sql.DBStats) {
	dbm.maxOpenConnections.Set(float64(dbStats.MaxOpenConnections))
	dbm.openConnections.Set(float64(dbStats.OpenConnections))
	dbm.inUse.Set(float64(dbStats.InUse))
	dbm.idle.Set(float64(dbStats.InUse))
	dbm.waitCount.Set(float64(dbStats.WaitCount))
	dbm.waitDuration.Observe(dbStats.WaitDuration.Seconds())
	dbm.maxIdleClosed.Set(float64(dbStats.MaxIdleClosed))
	dbm.maxLifetimeClosed.Set(float64(dbStats.MaxLifetimeClosed))
}

// reportDBMetrics is an infinite loop that will update the dbm with the gorp
// dbMap's inner sql.DBMap's DBStats structure every second. It is intended to
// be run in a dedicated goroutine spawned by InitDBMetrics.
func (dbm *dbMetrics) reportDBMetrics() {
	for {
		stats := dbm.dbMap.Db.Stats()
		dbm.updateFrom(stats)
		time.Sleep(1 * time.Second)
	}
}
