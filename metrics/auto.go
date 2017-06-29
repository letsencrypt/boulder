package metrics

import (
	"regexp"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// per `prometheus/common/model/metric.go` and the `IsValidMetricName` function
// only alphanumeric characters, underscore and `:` are valid characters in
// a Prometheus metric name
var invalidPromChars = regexp.MustCompile(`[^[:alnum:]\_:]+`)

// promAdjust adjusts a name for use by Prometheus: It and replaces "-" and "."
// with "_". Invalid metric name characters that remain (e.g. `>`) are removed.
func promAdjust(name string) string {
	name = strings.Replace(name, "-", "_", -1)
	name = strings.Replace(name, ".", "_", -1)
	return invalidPromChars.ReplaceAllString(name, "")
}

// autoProm implements a bridge from statsd-style metrics to Prometheus-style
// metrics, automatically registering metrics the first time they are used and
// memoizing them (since Prometheus doesn't allow repeat registration of the
// same metric). It is safe for concurrent access.
type autoProm struct {
	sync.RWMutex
	prometheus.Registerer
	metrics map[string]prometheus.Collector
}

type maker func(string) prometheus.Collector

func (ap *autoProm) get(name string, make maker) prometheus.Collector {
	name = promAdjust(name)
	ap.RLock()
	result := ap.metrics[name]
	ap.RUnlock()
	if result != nil {
		return result
	}
	ap.Lock()
	defer ap.Unlock()

	// Check once more, since it could have been added while we were locked.
	if ap.metrics[name] != nil {
		return ap.metrics[name]
	}
	result = make(name)
	ap.Registerer.MustRegister(result)
	ap.metrics[name] = result
	return result
}

func newAutoProm(registerer prometheus.Registerer) *autoProm {
	return &autoProm{
		metrics:    make(map[string]prometheus.Collector),
		Registerer: registerer,
	}
}

// autoRegisterer wraps three autoProm instances, one for each type of metric
// managed by this module, and provides methods to get/make those metrics.
type autoRegisterer struct {
	gauges, counters, summaries *autoProm
}

func newAutoRegisterer(registerer prometheus.Registerer) *autoRegisterer {
	return &autoRegisterer{
		gauges:    newAutoProm(registerer),
		counters:  newAutoProm(registerer),
		summaries: newAutoProm(registerer),
	}
}

func (ar *autoRegisterer) autoGauge(name string) prometheus.Gauge {
	return ar.gauges.get(name, func(cleaned string) prometheus.Collector {
		return prometheus.NewGauge(prometheus.GaugeOpts{
			Name: cleaned,
			Help: "auto",
		})
	}).(prometheus.Gauge)
}

func (ar *autoRegisterer) autoCounter(name string) prometheus.Counter {
	return ar.counters.get(name, func(cleaned string) prometheus.Collector {
		return prometheus.NewCounter(prometheus.CounterOpts{
			Name: cleaned,
			Help: "auto",
		})
	}).(prometheus.Counter)
}

func (ar *autoRegisterer) autoSummary(name string) prometheus.Summary {
	return ar.summaries.get(name, func(cleaned string) prometheus.Collector {
		return prometheus.NewSummary(prometheus.SummaryOpts{
			Name: cleaned,
			Help: "auto",
		})
	}).(prometheus.Summary)
}
