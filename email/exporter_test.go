package email

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	emailpb "github.com/letsencrypt/boulder/email/proto"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
)

var ctx = context.Background()

// MockPardotClientImpl is a mock implementation of PardotClient.
type MockPardotClientImpl struct {
	sync.Mutex
	CreatedContacts []string
}

// NewMockPardotClientImpl returns a MockPardotClientImpl, implementing the
// PardotClient interface. Both refer to the same instance, with the interface
// for mock interaction and the struct for state inspection and modification.
func NewMockPardotClientImpl() (PardotClient, *MockPardotClientImpl) {
	mockImpl := &MockPardotClientImpl{
		CreatedContacts: []string{},
	}
	return mockImpl, mockImpl
}

// SendContact adds an email to CreatedContacts.
func (m *MockPardotClientImpl) SendContact(email string) error {
	m.Lock()
	defer m.Unlock()

	m.CreatedContacts = append(m.CreatedContacts, email)
	return nil
}

func (m *MockPardotClientImpl) getCreatedContacts() []string {
	m.Lock()
	defer m.Unlock()
	// Return a copy to avoid race conditions.
	return append([]string(nil), m.CreatedContacts...)
}

// setup creates a new ExporterImpl, a MockPardotClientImpl, and the start and
// cleanup functions for the ExporterImpl. Call start() to begin processing the
// ExporterImpl queue and cleanup() to drain and shutdown. If start() is called,
// cleanup() must be called.
func setup() (*ExporterImpl, *MockPardotClientImpl, func(), func()) {
	mockClient, clientImpl := NewMockPardotClientImpl()
	exporter := NewExporterImpl(mockClient, 1000000, metrics.NoopRegisterer, blog.NewMock())
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

	_, err := exporter.SendContacts(ctx, &emailpb.SendContactsRequest{
		Emails: []string{"test@example.com", "user@example.com"},
	})

	// Wait for the queue to be processed.
	time.Sleep(100 * time.Millisecond)

	test.AssertNotError(t, err, "Error creating contacts")
	test.AssertEquals(t, 2, len(clientImpl.getCreatedContacts()))
}

func TestSendContactsQueueFull(t *testing.T) {
	t.Parallel()

	exporter, _, _, _ := setup()

	// Fill the queue.
	exporter.Lock()
	exporter.toSend = make([]string, queueCap-1)
	exporter.Unlock()

	_, err := exporter.SendContacts(ctx, &emailpb.SendContactsRequest{
		Emails: []string{"test@example.com", "user@example.com"},
	})
	test.AssertErrorIs(t, err, ErrQueueFull)
}

func TestSendContactsQueueDrains(t *testing.T) {
	t.Parallel()

	exporter, clientImpl, start, cleanup := setup()
	start()

	// Add 100 emails to the queue.
	var emails []string
	for i := range 100 {
		emails = append(emails, fmt.Sprintf("test@%d.example.com", i))
	}

	_, err := exporter.SendContacts(ctx, &emailpb.SendContactsRequest{
		Emails: emails,
	})
	test.AssertNotError(t, err, "Error creating contacts")

	// Drain the queue.
	cleanup()

	// Check that the queue was drained.
	test.AssertEquals(t, 100, len(clientImpl.getCreatedContacts()))
}
