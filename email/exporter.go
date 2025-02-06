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
	sync.RWMutex

	toSend []string
	client *PardotClient
	log    blog.Logger
}

// NewExporterImpl creates a new ExporterImpl.
func NewExporterImpl(client *PardotClient, scope prometheus.Registerer, logger blog.Logger) *ExporterImpl {
	impl := &ExporterImpl{
		toSend: make([]string, 0, queueCap),
		client: client,
		log:    logger,
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

// UpsertEmails enqueues the provided email addresses. If the queue is near
// capacity, only enqueues as many emails as can fit. Returns ErrQueueFull if
// some or all emails were dropped.
func (impl *ExporterImpl) UpsertEmails(ctx context.Context, req *exporterpb.UpsertEmailsRequest) (*emptypb.Empty, error) {
	if core.IsAnyNilOrZero(req, req.Emails) {
		return nil, berrors.InternalServerError("Incomplete UpsertEmails request")
	}

	impl.Lock()
	defer impl.Unlock()

	spotsLeft := queueCap - len(impl.toSend)
	if spotsLeft <= 0 {
		return nil, ErrQueueFull
	}

	toAdd := req.Emails
	if len(toAdd) > spotsLeft {
		toAdd = toAdd[:spotsLeft]
	}

	impl.toSend = append(impl.toSend, toAdd...)

	if len(toAdd) < len(req.Emails) {
		impl.log.Errf("Dropped %d emails due to queue capacity", len(req.Emails)-len(toAdd))
		return nil, ErrQueueFull
	}

	return &emptypb.Empty{}, nil
}

// takeEmail pops an email from the slice (LIFO).
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
// daemonCtx is cancelled switches into a draining mode.
func (impl *ExporterImpl) Start(daemonCtx context.Context) {
	limiter := rate.NewLimiter(rate.Limit(rateLimit), numWorkers)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		draining := false
		for {
			if daemonCtx.Err() != nil {
				draining = true
			}

			if draining {
				err := limiter.Wait(context.Background())
				if err != nil {
					// This should never happen, we're using a background
					// context.
					impl.log.Errf("While draining: limiter wait error: %s", err)
				}
			} else {
				err := limiter.Wait(daemonCtx)
				if err != nil {
					if errors.Is(err, context.Canceled) {
						draining = true
						continue
					}
					impl.log.Errf("While running: unexpected limiter wait error: %s", err)
					continue
				}
			}

			email, ok := impl.takeEmail()
			if !ok {
				if draining {
					return
				}
				// No emails to process, avoid busy-waiting.
				time.Sleep(100 * time.Millisecond)
				continue
			}

			err := impl.client.UpsertEmail(email)
			if err != nil {
				impl.log.Errf("Failed to upsert email: %s", err)
			}
		}
	}

	for range numWorkers {
		wg.Add(1)
		go worker()
	}
	<-daemonCtx.Done()
	wg.Wait()
}
