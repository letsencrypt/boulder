package ca

import (
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"

	blog "github.com/letsencrypt/boulder/log"
)

type ocspLogQueue struct {
	queue  chan ocspLog
	depth  prometheus.Gauge
	logger blog.Logger
}

type ocspLog struct {
	serial []byte
	time   time.Time
	status ocsp.ResponseStatus
}

func newOCSPLogQueue(stats prometheus.Registerer, logger blog.Logger) *ocspLogQueue {
	depth := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ocsp_log_queue_depth",
			Help: "Number of OCSP generation log entries waiting to be written",
		})
	stats.MustRegister(depth)
	return &ocspLogQueue{
		queue:  make(chan ocspLog, 10000),
		depth:  depth,
		logger: logger,
	}
}

func (olq *ocspLogQueue) enqueue(serial []byte, time time.Time, status ocsp.ResponseStatus) {
	olq.queue <- ocspLog{
		serial: serial,
		time:   time,
		status: ocsp.ResponseStatus(status),
	}
}

// loop consumes events from the queue channel, batches them up, and
// logs them in batches of 100, or every 500 milliseconds, whichever comes first.
func (olq *ocspLogQueue) loop() error {
	for {
		var builder strings.Builder
		deadline := time.After(500 * time.Millisecond)
	inner:
		for i := 0; i < 100; i++ {
			olq.depth.Set(float64(len(olq.queue)))
			select {
			case ol := <-olq.queue:
				fmt.Fprintf(&builder, "%x:%d,", ol.serial, ol.status)
			case <-deadline:
				break inner
			}
		}
		if builder.Len() > 0 {
			olq.logger.AuditInfof("OCSP updates: %s", builder.String())
		}
	}
}
