package email

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	emailpb "github.com/letsencrypt/boulder/email/proto"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/test"
)

var ctx = context.Background()

// MockPardotClientImpl is a mock implementation of PardotClient.
type MockPardotClientImpl struct {
	sync.Mutex
	CreatedProspects []string
}

// NewMockPardotClientImpl returns a MockPardotClientImpl, implementing the
// PardotClient interface. Both refer to the same instance, with the interface
// for mock interaction and the struct for state inspection and modification.
func NewMockPardotClientImpl() (PardotClient, *MockPardotClientImpl) {
	mockImpl := &MockPardotClientImpl{
		CreatedProspects: []string{},
	}
	return mockImpl, mockImpl
}

// CreateProspect adds an email to CreatedProspects.
func (m *MockPardotClientImpl) CreateProspect(email string) error {
	m.Lock()
	defer m.Unlock()

	m.CreatedProspects = append(m.CreatedProspects, email)
	return nil
}

func (m *MockPardotClientImpl) getCreatedProspects() []string {
	m.Lock()
	defer m.Unlock()
	// Return a copy to avoid race conditions.
	return append([]string(nil), m.CreatedProspects...)
}

func setup() (*ExporterImpl, *MockPardotClientImpl, func(), func()) {
	mockClient, clientImpl := NewMockPardotClientImpl()
	logger := blog.NewMock()
	scope := prometheus.NewRegistry()
	exporter := NewExporterImpl(mockClient, 1000000, scope, logger)

	daemonCtx, cancel := context.WithCancel(context.Background())

	return exporter, clientImpl,
		func() { exporter.Start(daemonCtx) },
		func() {
			cancel()
			exporter.Drain()
		}
}

func TestCreateProspects(t *testing.T) {
	t.Parallel()

	exporter, clientImpl, start, cleanup := setup()
	start()
	defer cleanup()

	_, err := exporter.CreateProspects(ctx, &emailpb.CreateProspectsRequest{
		Emails: []string{"test@example.com", "user@example.com"},
	})

	// Wait for the queue to be processed.
	time.Sleep(100 * time.Millisecond)

	test.AssertNotError(t, err, "Error creating prospects")
	test.AssertEquals(t, 2, len(clientImpl.getCreatedProspects()))
}

func TestCreateProspectsQueueFull(t *testing.T) {
	t.Parallel()

	exporter, _, _, _ := setup()

	// Fill the queue.
	exporter.Lock()
	exporter.toSend = make([]string, queueCap-1)
	exporter.Unlock()

	_, err := exporter.CreateProspects(ctx, &emailpb.CreateProspectsRequest{
		Emails: []string{"test@example.com", "user@example.com"},
	})
	test.AssertErrorIs(t, err, ErrQueueFull)
}

func TestCreateProspectsQueueDrains(t *testing.T) {
	t.Parallel()

	exporter, clientImpl, start, cleanup := setup()
	start()

	// Add 100 emails to the queue.
	var emails []string
	for i := range 100 {
		emails = append(emails, fmt.Sprintf("test@%d.example.com", i))
	}

	_, err := exporter.CreateProspects(ctx, &emailpb.CreateProspectsRequest{
		Emails: emails,
	})
	test.AssertNotError(t, err, "Error creating prospects")

	// Drain the queue.
	cleanup()

	// Check that the queue was drained.
	test.AssertEquals(t, 100, len(clientImpl.getCreatedProspects()))
}
