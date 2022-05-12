package rocsp

import (
	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus"
)

type metricsCollector struct {
	rdb *redis.ClusterClient

	// Stats accessible from the go-redis connector:
	// https://pkg.go.dev/github.com/go-redis/redis@v6.15.9+incompatible/internal/pool#Stats
	hits       *prometheus.Desc
	misses     *prometheus.Desc
	timeouts   *prometheus.Desc
	totalConns *prometheus.Desc
	idleConns  *prometheus.Desc
	staleConns *prometheus.Desc
}

// Describe is implemented with DescribeByCollect. That's possible because the
// Collect method will always return the same metrics with the same descriptors.
func (dbc metricsCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(dbc, ch)
}

// Collect first triggers the Redis ClusterClient's PoolStats function.
// Then it creates constant metrics for each Stats value on the fly based
// on the returned data.
//
// Note that Collect could be called concurrently, so we depend on PoolStats()
// to be concurrency-safe.
func (dbc metricsCollector) Collect(ch chan<- prometheus.Metric) {
	writeStat := func(stat *prometheus.Desc, typ prometheus.ValueType, val float64) {
		ch <- prometheus.MustNewConstMetric(stat, typ, val)
	}
	writeGauge := func(stat *prometheus.Desc, val float64) {
		writeStat(stat, prometheus.GaugeValue, val)
	}

	stats := dbc.rdb.PoolStats()
	writeGauge(dbc.hits, float64(stats.Hits))
	writeGauge(dbc.misses, float64(stats.Misses))
	writeGauge(dbc.timeouts, float64(stats.Timeouts))
	writeGauge(dbc.totalConns, float64(stats.TotalConns))
	writeGauge(dbc.idleConns, float64(stats.IdleConns))
	writeGauge(dbc.staleConns, float64(stats.StaleConns))
}

func newMetricsCollector(labels prometheus.Labels) metricsCollector {
	return metricsCollector{
		hits: prometheus.NewDesc(
			"redis_connection_pool_hits",
			"Number of times free connection was found in the pool.",
			nil, labels),
		misses: prometheus.NewDesc(
			"redis_redis_connection_pool_misses",
			"Number of times free connection was NOT found in the pool.",
			nil, labels),
		timeouts: prometheus.NewDesc(
			"redis_connection_pool_timeouts",
			"Number of times a wait timeout occurred.",
			nil, labels),
		totalConns: prometheus.NewDesc(
			"redis_connection_pool_total_conns",
			"Number of total connections in the pool.",
			nil, labels),
		idleConns: prometheus.NewDesc(
			"redis_connection_pool_idle_conns",
			"Number of idle connections in the pool.",
			nil, labels),
		staleConns: prometheus.NewDesc(
			"redis_connection_pool_stale_conns",
			"Number of stale connections removed from the pool.",
			nil, labels),
	}
}
