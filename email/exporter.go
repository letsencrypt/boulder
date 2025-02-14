package email

import (
	"context"
	"errors"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/letsencrypt/boulder/core"
	emailpb "github.com/letsencrypt/boulder/email/proto"
	berrors "github.com/letsencrypt/boulder/errors"
	blog "github.com/letsencrypt/boulder/log"
)

const (
	// five is the number of concurrent workers processing the email queue. This
	// number was chosen specifically to match the number of concurrent
	// connections allowed by the Pardot API.
	five = 5

	// queueCap enforces a maximum stack size to prevent unbounded growth.
	queueCap = 10000
)

var ErrQueueFull = errors.New("email-exporter queue is full")

// ExporterImpl implements the gRPC server and processes email exports.
type ExporterImpl struct {
	emailpb.UnsafeExporterServer

	sync.Mutex
	drainWG sync.WaitGroup
	wake    *sync.Cond

	limiter              *rate.Limiter
	toSend               []string
	client               PardotClient
	emailsHandledCounter prometheus.Counter
	log                  blog.Logger
}

var _ emailpb.ExporterServer = (*ExporterImpl)(nil)

// NewExporterImpl creates a new ExporterImpl.
func NewExporterImpl(client PardotClient, perDayLimit float64, scope prometheus.Registerer, logger blog.Logger) *ExporterImpl {
	// This limiter enforces the daily Pardot API limit and restricts
	// concurrency to the maximum of 5 requests specified in their
	// documentation. For more details see:
	// https://developer.salesforce.com/docs/marketing/pardot/guide/overview.html?q=rate%20limits
	limiter := rate.NewLimiter(rate.Limit(perDayLimit/86400.0), 5)

	emailsHandledCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "email_exporter_emails_handled",
		Help: "Total number of emails handled by the email exporter",
	})
	scope.MustRegister(emailsHandledCounter)

	impl := &ExporterImpl{
		limiter:              limiter,
		toSend:               make([]string, 0, queueCap),
		client:               client,
		emailsHandledCounter: emailsHandledCounter,
		log:                  logger,
	}
	impl.wake = sync.NewCond(&impl.Mutex)

	queueGauge := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "email_exporter_queue_length",
		Help: "Current length of the email export queue",
	}, func() float64 {
		impl.Lock()
		defer impl.Unlock()
		return float64(len(impl.toSend))
	})
	scope.MustRegister(queueGauge)

	return impl
}

// CreateProspects enqueues the provided email addresses. If the queue cannot
// accommodate the new emails, an ErrQueueFull is returned.
func (impl *ExporterImpl) CreateProspects(ctx context.Context, req *emailpb.CreateProspectsRequest) (*emptypb.Empty, error) {
	if core.IsAnyNilOrZero(req, req.Emails) {
		return nil, berrors.InternalServerError("Incomplete UpsertEmails request")
	}

	impl.Lock()
	spotsLeft := queueCap - len(impl.toSend)
	if spotsLeft < len(req.Emails) {
		return nil, ErrQueueFull
	}
	impl.toSend = append(impl.toSend, req.Emails...)
	impl.Unlock()
	// Wake waiting workers to process the new emails.
	impl.wake.Broadcast()

	return &emptypb.Empty{}, nil
}

// Start begins asynchronous processing of the email queue. When the parent
// daemonCtx is cancelled the queue will be drained and the workers will exit.
func (impl *ExporterImpl) Start(daemonCtx context.Context) {
	go func() {
		<-daemonCtx.Done()
		impl.Lock()
		// Wake waiting workers to exit.
		impl.wake.Broadcast()
		impl.Unlock()
	}()

	worker := func() {
		defer impl.drainWG.Done()
		for {
			impl.Lock()

			for len(impl.toSend) == 0 && daemonCtx.Err() == nil {
				// Wait for the queue to be updated or the daemon to exit.
				impl.wake.Wait()
			}

			if len(impl.toSend) == 0 && daemonCtx.Err() != nil {
				// No more emails to process, exit.
				impl.Unlock()
				return
			}

			// Dequeue and dispatch an email.
			last := len(impl.toSend) - 1
			email := impl.toSend[last]
			impl.toSend = impl.toSend[:last]
			impl.Unlock()

			err := impl.limiter.Wait(daemonCtx)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					impl.log.Errf("Unexpected limiter.Wait() error: %s", err)
					continue
				}
			}

			err = impl.client.CreateProspect(email)
			if err != nil {
				impl.log.Errf("Sending Prospect to Pardot: %s", err)
			}
			impl.emailsHandledCounter.Inc()
		}
	}

	for range five {
		impl.drainWG.Add(1)
		go worker()
	}
}

// Drain blocks until all workers have finished processing the email queue.
func (impl *ExporterImpl) Drain() {
	impl.drainWG.Wait()
}
