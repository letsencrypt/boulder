package email

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/letsencrypt/boulder/core"
	exporterpb "github.com/letsencrypt/boulder/email/proto"
	berrors "github.com/letsencrypt/boulder/errors"
	blog "github.com/letsencrypt/boulder/log"
)

const (
	// Our daily limit is determined by the tier of our Salesforce account. For
	// more information, see:
	// https://developer.salesforce.com/docs/marketing/pardot/guide/overview.html?q=rate%20limits

	// ratelimit represents our daily limit of 50,000 requests.
	rateLimit = 50000.0 / 86400.0

	// numWorkers is the number of concurrent workers processing the email
	// queue. We also use this as the burst limit for the rate limiter.
	numWorkers = 5

	// queueCap enforces a maximum stack size to prevent unbounded growth.
	queueCap = 10000
)

var ErrQueueFull = errors.New("email export queue is full")

// ExporterImpl implements the gRPC server and processes email exports.
type ExporterImpl struct {
	exporterpb.UnsafeExporterServer

	sync.RWMutex
	drainWG sync.WaitGroup

	toSend               []string
	client               *PardotClient
	emailsHandledCounter prometheus.Counter
	log                  blog.Logger
}

var _ exporterpb.ExporterServer = (*ExporterImpl)(nil)

// NewExporterImpl creates a new ExporterImpl.
func NewExporterImpl(client *PardotClient, scope prometheus.Registerer, logger blog.Logger) *ExporterImpl {
	emailsHandledCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "email_exporter_emails_handled",
		Help: "Total number of emails handled by the email exporter",
	})
	scope.MustRegister(emailsHandledCounter)

	impl := &ExporterImpl{
		toSend:               make([]string, 0, queueCap),
		client:               client,
		emailsHandledCounter: emailsHandledCounter,
		log:                  logger,
	}

	queueGauge := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "email_exporter_queue_length",
		Help: "Current length of the email export queue",
	}, func() float64 {
		impl.RLock()
		defer impl.RUnlock()
		return float64(len(impl.toSend))
	})
	scope.MustRegister(queueGauge)

	return impl
}

// CreateProspects enqueues the provided email addresses. If the queue is near
// capacity, only enqueues as many emails as can fit. Returns ErrQueueFull if
// some or all emails were dropped.
func (impl *ExporterImpl) CreateProspects(ctx context.Context, req *exporterpb.CreateProspectsRequest) (*emptypb.Empty, error) {
	if core.IsAnyNilOrZero(req, req.Emails) {
		return nil, berrors.InternalServerError("Incomplete UpsertEmails request")
	}

	impl.Lock()
	defer impl.Unlock()

	spotsLeft := queueCap - len(impl.toSend)
	if spotsLeft < len(req.Emails) {
		return nil, ErrQueueFull
	}
	impl.toSend = append(impl.toSend, req.Emails...)

	return &emptypb.Empty{}, nil
}

func (impl *ExporterImpl) takeEmail() (string, bool) {
	impl.Lock()
	defer impl.Unlock()

	if len(impl.toSend) == 0 {
		return "", false
	}

	email := impl.toSend[len(impl.toSend)-1]
	impl.toSend = impl.toSend[:len(impl.toSend)-1]

	return email, true
}

// Start begins asynchronous processing of the email queue. When the parent
// daemonCtx is cancelled the queue will be drained and the workers will exit.
func (impl *ExporterImpl) Start(daemonCtx context.Context) {
	limiter := rate.NewLimiter(rate.Limit(rateLimit), numWorkers)

	worker := func() {
		defer impl.drainWG.Done()
		for {
			if daemonCtx.Err() != nil && len(impl.toSend) == 0 {
				return
			}

			err := limiter.Wait(daemonCtx)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					// Keep processing emails until the queue is drained.
					continue
				}
				impl.log.Errf("Unexpected limiter wait error: %s", err)
				continue
			}

			email, ok := impl.takeEmail()
			if !ok {
				if daemonCtx.Err() != nil {
					// Exit immediately.
					return
				}
				// No emails to process, avoid busy-waiting.
				time.Sleep(100 * time.Millisecond)
				continue
			}

			err = impl.client.CreateProspect(email)
			if err != nil {
				impl.log.Errf("Failed to upsert email: %s", err)
			}
			impl.emailsHandledCounter.Inc()
		}
	}

	for range numWorkers {
		impl.drainWG.Add(1)
		go worker()
	}
}

// Drain blocks until all workers have finished processing the email queue.
func (impl *ExporterImpl) Drain() {
	impl.drainWG.Wait()
}
