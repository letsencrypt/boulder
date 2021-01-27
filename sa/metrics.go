package sa

import (
	"github.com/letsencrypt/boulder/db"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	maxOpenConns = prometheus.NewDesc(
		"db_max_open_connections",
		"Maximum number of DB connections allowed.",
		nil, nil)

	maxIdleConns = prometheus.NewDesc(
		"db_max_idle_connections",
		"Maximum number of idle DB connections allowed.",
		nil, nil)

	connMaxLifetime = prometheus.NewDesc(
		"db_connection_max_lifetime",
		"Maximum lifetime of DB connections allowed.",
		nil, nil)

	connMaxIdleTime = prometheus.NewDesc(
		"db_connection_max_idle_time",
		"Maximum lifetime of idle DB connections allowed.",
		nil, nil)

	openConns = prometheus.NewDesc(
		"db_open_connections",
		"Number of established DB connections (in-use and idle).",
		nil, nil)

	inUse = prometheus.NewDesc(
		"db_inuse",
		"Number of DB connections currently in use.",
		nil, nil)

	idle = prometheus.NewDesc(
		"db_idle",
		"Number of idle DB connections.",
		nil, nil)

	waitCount = prometheus.NewDesc(
		"db_wait_count",
		"Total number of DB connections waited for.",
		nil, nil)

	waitDuration = prometheus.NewDesc(
		"db_wait_duration_seconds",
		"The total time blocked waiting for a new connection.",
		nil, nil)

	maxIdleClosed = prometheus.NewDesc(
		"db_max_idle_closed",
		"Total number of connections closed due to SetMaxIdleConns.",
		nil, nil)

	maxLifetimeClosed = prometheus.NewDesc(
		"db_max_lifetime_closed",
		"Total number of connections closed due to SetConnMaxLifetime.",
		nil, nil)
)

type dbMetricsCollector struct {
	dbMap      *db.WrappedMap
	dbSettings DbSettings
}

// Describe is implemented with DescribeByCollect. That's possible because the
// Collect method will always return the same metrics with the same descriptors.
func (dbc dbMetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(dbc, ch)
}

// Collect first triggers the dbMaps's sql.Db's Stats function. Then it
// creates constant metrics for each DBStats value on the fly based on the
// returned data.
//
// Note that Collect could be called concurrently, so we depend on
// Stats() to be concurrency-safe.
func (dbc dbMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	writeStat := func(stat *prometheus.Desc, typ prometheus.ValueType, val float64) {
		ch <- prometheus.MustNewConstMetric(stat, typ, val)
	}
	writeCounter := func(stat *prometheus.Desc, val float64) {
		writeStat(stat, prometheus.CounterValue, val)
	}
	writeGauge := func(stat *prometheus.Desc, val float64) {
		writeStat(stat, prometheus.GaugeValue, val)
	}

	// Translate the DBMap's db.DBStats counter values into Prometheus metrics.
	dbMapStats := dbc.dbMap.Db.Stats()
	writeGauge(maxOpenConns, float64(dbMapStats.MaxOpenConnections))
	writeGauge(maxIdleConns, float64(dbc.dbSettings.MaxIdleConns))
	writeGauge(connMaxLifetime, float64(dbc.dbSettings.ConnMaxLifetime))
	writeGauge(connMaxIdleTime, float64(dbc.dbSettings.ConnMaxIdleTime))
	writeGauge(openConns, float64(dbMapStats.OpenConnections))
	writeGauge(inUse, float64(dbMapStats.InUse))
	writeGauge(idle, float64(dbMapStats.Idle))
	writeCounter(waitCount, float64(dbMapStats.WaitCount))
	writeCounter(waitDuration, dbMapStats.WaitDuration.Seconds())
	writeCounter(maxIdleClosed, float64(dbMapStats.MaxIdleClosed))
	writeCounter(maxLifetimeClosed, float64(dbMapStats.MaxLifetimeClosed))
}

// InitDBMetrics will register a Collector that translates the provided dbMap's
// stats and DbSettings into Prometheus metrics on the fly. The stat values will
// be translated from the gorp dbMap's inner sql.DBMap's DBStats structure values
func InitDBMetrics(dbMap *db.WrappedMap, stats prometheus.Registerer, dbSettings DbSettings) {
	// Create a dbMetricsCollector and register it
	dbc := dbMetricsCollector{dbMap, dbSettings}
	stats.MustRegister(dbc)
}
