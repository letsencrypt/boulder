package salesforce

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	salesforcepb "github.com/letsencrypt/boulder/salesforce/proto"
	"github.com/letsencrypt/boulder/test"

	"github.com/prometheus/client_golang/prometheus"
)

var ctx = context.Background()

var _ SalesforceClient = (*mockSalesforceClientImpl)(nil)

// mockSalesforceClientImpl is a mock implementation of PardotClient.
type mockSalesforceClientImpl struct {
	SalesforceClient

	sync.Mutex
	CreatedContacts []string
	CreatedCases    []Case
}

// newMockSalesforceClientImpl returns a mockSalesforceClientImpl, which implements
// the PardotClient interface. It returns the underlying concrete type, so callers
// have access to its struct members and helper methods.
func newMockSalesforceClientImpl() *mockSalesforceClientImpl {
	return &mockSalesforceClientImpl{}
}

// SendContact adds an email to CreatedContacts.
func (m *mockSalesforceClientImpl) SendContact(email string) error {
	m.Lock()
	defer m.Unlock()
	m.CreatedContacts = append(m.CreatedContacts, email)
	return nil
}

func (m *mockSalesforceClientImpl) getCreatedContacts() []string {
	m.Lock()
	defer m.Unlock()

	// Return a copy to avoid race conditions.
	return slices.Clone(m.CreatedContacts)
}

func (m *mockSalesforceClientImpl) SendCase(payload Case) error {
	m.Lock()
	defer m.Unlock()
	m.CreatedCases = append(m.CreatedCases, payload)
	return nil
}

func (m *mockSalesforceClientImpl) getCreatedCases() []Case {
	m.Lock()
	defer m.Unlock()

	// Return a copy to avoid race conditions.
	return slices.Clone(m.CreatedCases)
}

// setup creates a new ExporterImpl, a mockSalesForceClientImpl, and the start and
// cleanup functions for the ExporterImpl. Call start() to begin processing the
// ExporterImpl queue and cleanup() to drain and shutdown. If start() is called,
// cleanup() must be called.
func setup() (*ExporterImpl, *mockSalesforceClientImpl, func(), func()) {
	clientImpl := newMockSalesforceClientImpl()
	exporter := NewExporterImpl(clientImpl, nil, 1000000, 5, metrics.NoopRegisterer, blog.NewMock())
	daemonCtx, cancel := context.WithCancel(context.Background())
	return exporter, clientImpl,
		func() { exporter.Start(daemonCtx) },
		func() {
			cancel()
			exporter.Drain()
		}
}

func TestSendContacts(t *testing.T) {
	t.Parallel()

	exporter, clientImpl, start, cleanup := setup()
	start()
	defer cleanup()

	wantContacts := []string{"test@example.com", "user@example.com"}
	_, err := exporter.SendContacts(ctx, &salesforcepb.SendContactsRequest{
		Emails: wantContacts,
	})
	test.AssertNotError(t, err, "Error creating contacts")

	var gotContacts []string
	for range 100 {
		gotContacts = clientImpl.getCreatedContacts()
		if len(gotContacts) == 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	test.AssertSliceContains(t, gotContacts, wantContacts[0])
	test.AssertSliceContains(t, gotContacts, wantContacts[1])

	// Check that the error counter was not incremented.
	test.AssertMetricWithLabelsEquals(t, exporter.pardotErrorCounter, prometheus.Labels{}, 0)
}

func TestSendContactsQueueFull(t *testing.T) {
	t.Parallel()

	exporter, _, start, cleanup := setup()
	start()
	defer cleanup()

	var err error
	for range contactsQueueCap * 2 {
		_, err = exporter.SendContacts(ctx, &salesforcepb.SendContactsRequest{
			Emails: []string{"test@example.com"},
		})
		if err != nil {
			break
		}
	}
	test.AssertErrorIs(t, err, ErrQueueFull)
}

func TestSendContactsQueueDrains(t *testing.T) {
	t.Parallel()

	exporter, clientImpl, start, cleanup := setup()
	start()

	var emails []string
	for i := range 100 {
		emails = append(emails, fmt.Sprintf("test@%d.example.com", i))
	}

	_, err := exporter.SendContacts(ctx, &salesforcepb.SendContactsRequest{
		Emails: emails,
	})
	test.AssertNotError(t, err, "Error creating contacts")

	// Drain the queue.
	cleanup()

	test.AssertEquals(t, 100, len(clientImpl.getCreatedContacts()))
}

type mockAlwaysFailClient struct {
	mockSalesforceClientImpl
}

func (m *mockAlwaysFailClient) SendContact(email string) error {
	return fmt.Errorf("simulated failure")
}

func TestSendContactsErrorMetrics(t *testing.T) {
	t.Parallel()

	mockClient := &mockAlwaysFailClient{}
	exporter := NewExporterImpl(mockClient, nil, 1000000, 5, metrics.NoopRegisterer, blog.NewMock())

	daemonCtx, cancel := context.WithCancel(context.Background())
	exporter.Start(daemonCtx)

	_, err := exporter.SendContacts(ctx, &salesforcepb.SendContactsRequest{
		Emails: []string{"test@example.com"},
	})
	test.AssertNotError(t, err, "Error creating contacts")

	// Drain the queue.
	cancel()
	exporter.Drain()

	// Check that the error counter was incremented.
	test.AssertMetricWithLabelsEquals(t, exporter.pardotErrorCounter, prometheus.Labels{}, 1)
}

func TestSendContactDeduplication(t *testing.T) {
	t.Parallel()

	cache := NewHashedEmailCache(1000, metrics.NoopRegisterer)
	clientImpl := newMockSalesforceClientImpl()
	exporter := NewExporterImpl(clientImpl, cache, 1000000, 5, metrics.NoopRegisterer, blog.NewMock())

	daemonCtx, cancel := context.WithCancel(context.Background())
	exporter.Start(daemonCtx)

	_, err := exporter.SendContacts(ctx, &salesforcepb.SendContactsRequest{
		Emails: []string{"duplicate@example.com", "duplicate@example.com"},
	})
	test.AssertNotError(t, err, "Error enqueuing contacts")

	// Drain the queue.
	cancel()
	exporter.Drain()

	contacts := clientImpl.getCreatedContacts()
	test.AssertEquals(t, 1, len(contacts))
	test.AssertEquals(t, "duplicate@example.com", contacts[0])

	// Only one successful send should be recorded.
	test.AssertMetricWithLabelsEquals(t, exporter.emailsHandledCounter, prometheus.Labels{}, 1)

	if !cache.Seen("duplicate@example.com") {
		t.Errorf("duplicate@example.com should have been cached after send")
	}
}

func TestSendContactErrorRemovesFromCache(t *testing.T) {
	t.Parallel()

	cache := NewHashedEmailCache(1000, metrics.NoopRegisterer)
	fc := &mockAlwaysFailClient{}

	exporter := NewExporterImpl(fc, cache, 1000000, 1, metrics.NoopRegisterer, blog.NewMock())

	daemonCtx, cancel := context.WithCancel(context.Background())
	exporter.Start(daemonCtx)

	_, err := exporter.SendContacts(ctx, &salesforcepb.SendContactsRequest{
		Emails: []string{"error@example.com"},
	})
	test.AssertNotError(t, err, "enqueue failed")

	// Drain the queue.
	cancel()
	exporter.Drain()

	// The email should have been evicted from the cache after send encountered
	// an error.
	if cache.Seen("error@example.com") {
		t.Errorf("error@example.com should have been evicted from cache after send errors")
	}

	// Check that the error counter was incremented.
	test.AssertMetricWithLabelsEquals(t, exporter.pardotErrorCounter, prometheus.Labels{}, 1)
}

func TestSendCase(t *testing.T) {
	t.Parallel()

	clientImpl := newMockSalesforceClientImpl()
	exporter := NewExporterImpl(clientImpl, nil, 1000000, 5, metrics.NoopRegisterer, blog.NewMock())

	_, err := exporter.SendCase(ctx, &salesforcepb.SendCaseRequest{
		Origin:       "Web",
		Subject:      "Some Override",
		Description:  "Please review",
		ContactEmail: "foo@example.com",
	})
	test.AssertNotError(t, err, "SendCase should succeed")

	got := clientImpl.getCreatedCases()
	if len(got) != 1 {
		t.Fatalf("expected 1 case, got %d", len(got))
	}
	test.AssertEquals(t, got[0].Origin, "Web")
	test.AssertEquals(t, got[0].Subject, "Some Override")
	test.AssertEquals(t, got[0].Description, "Please review")
	test.AssertEquals(t, got[0].ContactEmail, "foo@example.com")
	test.AssertMetricWithLabelsEquals(t, exporter.caseErrorCounter, prometheus.Labels{}, 0)
}

type mockAlwaysFailCaseClient struct {
	mockSalesforceClientImpl
}

func (m *mockAlwaysFailCaseClient) SendCase(payload Case) error {
	return fmt.Errorf("oops, lol")
}

func TestSendCaseClientErrorIncrementsMetric(t *testing.T) {
	t.Parallel()

	mockClient := &mockAlwaysFailCaseClient{}
	exporter := NewExporterImpl(mockClient, nil, 1000000, 5, metrics.NoopRegisterer, blog.NewMock())

	_, err := exporter.SendCase(ctx, &salesforcepb.SendCaseRequest{
		Origin:       "Web",
		Subject:      "Some Override",
		Description:  "Please review",
		ContactEmail: "foo@bar.baz",
	})
	test.AssertError(t, err, "SendCase should return error on client failure")
	test.AssertMetricWithLabelsEquals(t, exporter.caseErrorCounter, prometheus.Labels{}, 1)
}

func TestSendCaseMissingOriginValidation(t *testing.T) {
	t.Parallel()

	clientImpl := newMockSalesforceClientImpl()
	exporter := NewExporterImpl(clientImpl, nil, 1000000, 5, metrics.NoopRegisterer, blog.NewMock())

	_, err := exporter.SendCase(ctx, &salesforcepb.SendCaseRequest{Subject: "No origin in this one, d00d"})
	test.AssertError(t, err, "SendCase should fail validation when Origin is missing")

	got := clientImpl.getCreatedCases()
	if len(got) != 0 {
		t.Errorf("expected 0 cases due to validation error, got %d", len(got))
	}
	test.AssertMetricWithLabelsEquals(t, exporter.caseErrorCounter, prometheus.Labels{}, 0)
}
