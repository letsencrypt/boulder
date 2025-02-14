package mocks

import (
	"context"
	"fmt"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/letsencrypt/boulder/email"
	emailpb "github.com/letsencrypt/boulder/email/proto"
)

// MockPardotClientImpl is a mock implementation of PardotClient.
type MockPardotClientImpl struct {
	sync.Mutex
	CreatedProspects []string
	ForceCreateError bool
}

// NewMockPardotClientImpl returns a MockPardotClientImpl, implementing the
// PardotClient interface. Both refer to the same instance, with the interface
// for mock interaction and the struct for state inspection and modification.
func NewMockPardotClientImpl() (email.PardotClient, *MockPardotClientImpl) {
	mockImpl := &MockPardotClientImpl{
		CreatedProspects: []string{},
		ForceCreateError: false,
	}
	return mockImpl, mockImpl
}

// CreateProspect adds an email to CreatedProspects. Returns an error if
// ForceCreateError is set.
func (m *MockPardotClientImpl) CreateProspect(email string) error {
	m.Lock()
	defer m.Unlock()

	if m.ForceCreateError {
		return fmt.Errorf("error creating prospect")
	}

	m.CreatedProspects = append(m.CreatedProspects, email)
	return nil
}

// MockExporterClientImpl is a mock implementation of ExporterClient.
type MockExporterClientImpl struct {
	PardotClient email.PardotClient
}

// NewMockExporterImpl returns a MockExporterClientImpl as an
// ExporterClient.
func NewMockExporterImpl(pardotClient email.PardotClient) emailpb.ExporterClient {
	return &MockExporterClientImpl{
		PardotClient: pardotClient,
	}
}

// CreateProspects submits emails to the inner PardotClient, returning an error
// if any fail.
func (m *MockExporterClientImpl) CreateProspects(ctx context.Context, req *emailpb.CreateProspectsRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	for _, e := range req.Emails {
		if err := m.PardotClient.CreateProspect(e); err != nil {
			return nil, err
		}
	}
	return &emptypb.Empty{}, nil
}
