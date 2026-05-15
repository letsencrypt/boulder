package mocks

import (
	"context"
	"slices"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/letsencrypt/boulder/salesforce"
	salesforcepb "github.com/letsencrypt/boulder/salesforce/proto"
)

var _ salesforce.SalesforceClient = (*MockSalesforceClientImpl)(nil)

// MockSalesforceClientImpl is a mock implementation of salesforce.SalesforceClient.
type MockSalesforceClientImpl struct {
	sync.Mutex
	CreatedContacts []string
}

// NewMockSalesforceClientImpl returns a MockSalesforceClientImpl, which implements
// the PardotClient interface. It returns the underlying concrete type, so callers
// have access to its struct members and helper methods.
func NewMockSalesforceClientImpl() *MockSalesforceClientImpl {
	return &MockSalesforceClientImpl{}
}

// SendContact adds an email to CreatedContacts.
func (m *MockSalesforceClientImpl) SendContact(email string) error {
	m.Lock()
	defer m.Unlock()

	m.CreatedContacts = append(m.CreatedContacts, email)
	return nil
}

// GetCreatedContacts is used for testing to retrieve the list of created
// contacts in a thread-safe manner.
func (m *MockSalesforceClientImpl) GetCreatedContacts() []string {
	m.Lock()
	defer m.Unlock()

	// Return a copy to avoid race conditions.
	return slices.Clone(m.CreatedContacts)
}

var _ salesforcepb.ExporterClient = (*MockExporterClientImpl)(nil)

// MockExporterClientImpl is a mock implementation of ExporterClient.
type MockExporterClientImpl struct {
	SalesforceClient salesforce.SalesforceClient
}

// NewMockExporterImpl returns a MockExporterClientImpl as an ExporterClient.
func NewMockExporterImpl(salesforceClient salesforce.SalesforceClient) salesforcepb.ExporterClient {
	return &MockExporterClientImpl{
		SalesforceClient: salesforceClient,
	}
}

// SendContacts submits emails to the inner salesforce.SalesforceClient, returning an
// error if any fail.
func (m *MockExporterClientImpl) SendContacts(ctx context.Context, req *salesforcepb.SendContactsRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	for _, e := range req.Emails {
		err := m.SalesforceClient.SendContact(e)
		if err != nil {
			return nil, err
		}
	}
	return &emptypb.Empty{}, nil
}
