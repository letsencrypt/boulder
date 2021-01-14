package ca

// TODO(##5226): Move the GenerateOCSP service into this file too.

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"

	blog "github.com/letsencrypt/boulder/log"
)

// ocspLogQueue accumulates OCSP logging events and writes several of them
// in a single log line. This reduces the number of log lines and bytes,
// which would otherwise be quite high. As of Jan 2021 we do approximately
// 550 rps of OCSP generation events. We can turn that into about 5.5 rps
// of log lines if we accumulate 100 entries per line, which amounts to about
// 3900 bytes per log line.
// Summary of log line usage:
// serial in hex: 36 bytes, separator characters: 2 bytes, status: 1 byte
// If maxLogLen is less than the length of a single log item, generate
// one log line for every item.
type ocspLogQueue struct {
	// Maximum length, in bytes, of a single log line.
	maxLogLen int
	// Maximum amount of time between OCSP logging events.
	period time.Duration
	queue  chan ocspLog
	// This allows the stop() function to block until we've drained the queue.
	wg     sync.WaitGroup
	depth  prometheus.Gauge
	logger blog.Logger
	clk    clock.Clock
}

type ocspLog struct {
	serial []byte
	time   time.Time
	status ocsp.ResponseStatus
}

func newOCSPLogQueue(
	maxLogLen int,
	period time.Duration,
	stats prometheus.Registerer,
	logger blog.Logger,
) *ocspLogQueue {
	depth := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ocsp_log_queue_depth",
			Help: "Number of OCSP generation log entries waiting to be written",
		})
	stats.MustRegister(depth)
	olq := ocspLogQueue{
		maxLogLen: maxLogLen,
		period:    period,
		queue:     make(chan ocspLog),
		wg:        sync.WaitGroup{},
		depth:     depth,
		logger:    logger,
		clk:       clock.Default(),
	}
	olq.wg.Add(1)
	return &olq
}

func (olq *ocspLogQueue) enqueue(serial []byte, time time.Time, status ocsp.ResponseStatus) {
	olq.queue <- ocspLog{
		serial: append([]byte{}, serial...),
		time:   time,
		status: status,
	}
}

// To ensure we don't go over the max log line length, use a safety margin
// equal to the expected length of an entry.
const ocspSingleLogEntryLen = 39

// loop consumes events from the queue channel, batches them up, and
// logs them in batches of maxLogLen / 39, or every `period`,
// whichever comes first.
func (olq *ocspLogQueue) loop() {
	defer olq.wg.Done()
	done := false
	for !done {
		var builder strings.Builder
		deadline := olq.clk.After(olq.period)
	inner:
		for {
			olq.depth.Set(float64(len(olq.queue)))
			select {
			case ol, ok := <-olq.queue:
				if !ok {
					// Channel was closed, finish.
					done = true
					break inner
				}
				fmt.Fprintf(&builder, "%x:%d,", ol.serial, ol.status)
			case <-deadline:
				break inner
			}
			if builder.Len()+ocspSingleLogEntryLen >= olq.maxLogLen {
				break
			}
		}
		if builder.Len() > 0 {
			olq.logger.AuditInfof("OCSP signed: %s", builder.String())
		}
	}
}

// stop the loop, and wait for it to finish. This must be called only after
// it's guaranteed that nothing will call enqueue again (for instance, after
// the OCSPGenerator and CertificateAuthority services are shut down with
// no RPCs in flight). Otherwise, enqueue will panic.
// If this is called without previously starting a goroutine running `.loop()`,
// it will block forever.
func (olq *ocspLogQueue) stop() {
	close(olq.queue)
	olq.wg.Wait()
}
