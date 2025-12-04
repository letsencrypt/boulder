package email

import (
	"context"
	"errors"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/letsencrypt/boulder/core"
	emailpb "github.com/letsencrypt/boulder/email/proto"
	berrors "github.com/letsencrypt/boulder/errors"
	blog "github.com/letsencrypt/boulder/log"
)

// contactsQueueCap limits the queue size to prevent unbounded growth. This
// value is adjustable as needed. Each RFC 5321 email address, encoded in UTF-8,
// is at most 320 bytes. Storing 100,000 emails requires ~34.4 MB of memory.
const contactsQueueCap = 100000

var ErrQueueFull = errors.New("email-exporter queue is full")

// ExporterImpl implements the gRPC server and processes email exports.
type ExporterImpl struct {
	emailpb.UnsafeExporterServer

	sync.Mutex
	drainWG sync.WaitGroup
	// wake is used to signal workers when new emails are enqueued in toSend.
	// The sync.Cond docs note that "For many simple use cases, users will be
	// better off using channels." However, channels enforce FIFO ordering,
	// while this implementation uses a LIFO queue. Making channels behave as
	// LIFO would require extra complexity. Using a slice and broadcasting is
	// simpler and achieves exactly what we need.
	wake   *sync.Cond
	toSend []string

	maxConcurrentRequests int
	limiter               *rate.Limiter
	client                SalesforceClient
	emailCache            *EmailCache
	emailsHandledCounter  prometheus.Counter
	pardotErrorCounter    prometheus.Counter
	caseErrorCounter      prometheus.Counter
	log                   blog.Logger
}

var _ emailpb.ExporterServer = (*ExporterImpl)(nil)

// NewExporterImpl initializes an ExporterImpl with the given client and
// configuration. Both perDayLimit and maxConcurrentRequests should be
// distributed proportionally among instances based on their share of the daily
// request cap. For example, if the total daily limit is 50,000 and one instance
// is assigned 40% (20,000 requests), it should also receive 40% of the max
// concurrent requests (e.g., 2 out of 5). For more details, see:
// https://developer.salesforce.com/docs/marketing/pardot/guide/overview.html?q=rate%20limits
func NewExporterImpl(client SalesforceClient, cache *EmailCache, perDayLimit float64, maxConcurrentRequests int, stats prometheus.Registerer, logger blog.Logger) *ExporterImpl {
	limiter := rate.NewLimiter(rate.Limit(perDayLimit/86400.0), maxConcurrentRequests)

	emailsHandledCounter := promauto.With(stats).NewCounter(prometheus.CounterOpts{
		Name: "email_exporter_emails_handled",
		Help: "Total number of emails handled by the email exporter",
	})

	pardotErrorCounter := promauto.With(stats).NewCounter(prometheus.CounterOpts{
		Name: "email_exporter_errors",
		Help: "Total number of Pardot API errors encountered by the email exporter",
	})

	caseErrorCounter := promauto.With(stats).NewCounter(prometheus.CounterOpts{
		Name: "email_exporter_case_errors",
		Help: "Total number of errors encountered when sending Cases to the Salesforce REST API",
	})

	impl := &ExporterImpl{
		maxConcurrentRequests: maxConcurrentRequests,
		limiter:               limiter,
		toSend:                make([]string, 0, contactsQueueCap),
		client:                client,
		emailCache:            cache,
		emailsHandledCounter:  emailsHandledCounter,
		pardotErrorCounter:    pardotErrorCounter,
		caseErrorCounter:      caseErrorCounter,
		log:                   logger,
	}
	impl.wake = sync.NewCond(&impl.Mutex)

	// This metric doesn't need to be part of impl, since it computes itself
	// each time it is scraped.
	promauto.With(stats).NewGaugeFunc(prometheus.GaugeOpts{
		Name: "email_exporter_queue_length",
		Help: "Current length of the email export queue",
	}, func() float64 {
		impl.Lock()
		defer impl.Unlock()
		return float64(len(impl.toSend))
	})

	return impl
}

// SendContacts enqueues the provided email addresses. If the queue cannot
// accommodate the new emails, an ErrQueueFull is returned.
func (impl *ExporterImpl) SendContacts(ctx context.Context, req *emailpb.SendContactsRequest) (*emptypb.Empty, error) {
	if core.IsAnyNilOrZero(req, req.Emails) {
		return nil, berrors.InternalServerError("Incomplete gRPC request message")
	}

	impl.Lock()
	defer impl.Unlock()

	spotsLeft := contactsQueueCap - len(impl.toSend)
	if spotsLeft < len(req.Emails) {
		return nil, ErrQueueFull
	}
	impl.toSend = append(impl.toSend, req.Emails...)
	// Wake waiting workers to process the new emails.
	impl.wake.Broadcast()

	return &emptypb.Empty{}, nil
}

// SendCase immediately submits a new Case to the Salesforce REST API using the
// provided details. Any retries are handled internally by the SalesforceClient.
// The following fields are required: Origin, Subject, ContactEmail.
func (impl *ExporterImpl) SendCase(ctx context.Context, req *emailpb.SendCaseRequest) (*emptypb.Empty, error) {
	if core.IsAnyNilOrZero(req, req.Origin, req.Subject, req.ContactEmail) {
		return nil, berrors.InternalServerError("incomplete gRPC request message")
	}

	err := impl.client.SendCase(Case{
		Origin:        req.Origin,
		Subject:       req.Subject,
		Description:   req.Description,
		ContactEmail:  req.ContactEmail,
		Organization:  req.Organization,
		AccountId:     req.AccountId,
		RateLimitName: req.RateLimitName,
		RateLimitTier: req.RateLimitTier,
		UseCase:       req.UseCase,
	})
	if err != nil {
		impl.caseErrorCounter.Inc()
		return nil, berrors.InternalServerError("sending Case to the Salesforce REST API: %s", err)
	}

	return &emptypb.Empty{}, nil
}

// Start begins asynchronous processing of the email queue. When the parent
// daemonCtx is cancelled the queue will be drained and the workers will exit.
func (impl *ExporterImpl) Start(daemonCtx context.Context) {
	go func() {
		<-daemonCtx.Done()
		// Wake waiting workers to exit.
		impl.wake.Broadcast()
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

			if !impl.emailCache.StoreIfAbsent(email) {
				// Another worker has already processed this email.
				continue
			}

			err := impl.limiter.Wait(daemonCtx)
			if err != nil && !errors.Is(err, context.Canceled) {
				impl.log.Errf("Unexpected limiter.Wait() error: %s", err)
				continue
			}

			err = impl.client.SendContact(email)
			if err != nil {
				impl.emailCache.Remove(email)
				impl.pardotErrorCounter.Inc()
				impl.log.Errf("Sending Contact to Pardot: %s", err)
			} else {
				impl.emailsHandledCounter.Inc()
			}
		}
	}

	for range impl.maxConcurrentRequests {
		impl.drainWG.Add(1)
		go worker()
	}
}

// Drain blocks until all workers have finished processing the email queue.
func (impl *ExporterImpl) Drain() {
	impl.drainWG.Wait()
}
