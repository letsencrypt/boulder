package metrics

import (
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// promAdjust adjusts a name for use by Prometheus: It strips off a single label
// of prefix (which is always the name of the service, and therefore duplicated
// by Prometheus' instance labels), and replaces "-" and "." with "_".
func promAdjust(name string) string {
	name = strings.Replace(name, "-", "_", -1)
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return labels[0]
	}
	return strings.Join(labels[1:], "_")
}

// autoProm implements a bridge from statsd-style metrics to Prometheus-style
// metrics, automatically registering metrics the first time they are used and
// memoizing them (since Prometheus doesn't allow repeat registration of the
// same metric). It is safe for concurrent access.
type autoProm struct {
	sync.RWMutex
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
	prometheus.MustRegister(result)
	ap.metrics[name] = result
	return result
}

func newAutoProm() *autoProm {
	return &autoProm{
		metrics: make(map[string]prometheus.Collector),
	}
}

var gauges = newAutoProm()
var counters = newAutoProm()
var summaries = newAutoProm()

func autoGauge(name string) prometheus.Gauge {
	return gauges.get(name, func(cleaned string) prometheus.Collector {
		return prometheus.NewGauge(prometheus.GaugeOpts{
			Name: cleaned,
			Help: "auto",
		})
	}).(prometheus.Gauge)
}

func autoCounter(name string) prometheus.Counter {
	return counters.get(name, func(cleaned string) prometheus.Collector {
		return prometheus.NewCounter(prometheus.CounterOpts{
			Name: cleaned,
			Help: "auto",
		})
	}).(prometheus.Counter)
}

func autoSummary(name string) prometheus.Summary {
	return summaries.get(name, func(cleaned string) prometheus.Collector {
		return prometheus.NewSummary(prometheus.SummaryOpts{
			Name: cleaned,
			Help: "auto",
		})
	}).(prometheus.Summary)
}
