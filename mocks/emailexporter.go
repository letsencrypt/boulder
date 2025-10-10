package mocks

import (
	"context"
	"slices"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/letsencrypt/boulder/email"
	emailpb "github.com/letsencrypt/boulder/email/proto"
)

var _ email.SalesforceClient = (*MockSalesforceClientImpl)(nil)

// MockSalesforceClientImpl is a mock implementation of email.SalesforceClient.
type MockSalesforceClientImpl struct {
	sync.Mutex
	CreatedContacts []string
	CreatedCases    []email.Case
}

// NewMockSalesforceClientImpl returns a email.SalesforceClient and a
// *MockSalesforceClientImpl. Both refer to the same instance, with the
// interface for mock interaction and the struct for state inspection and
// modification.
func NewMockSalesforceClientImpl() (email.SalesforceClient, *MockSalesforceClientImpl) {
	mockImpl := &MockSalesforceClientImpl{}
	return mockImpl, mockImpl
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

// SendCase adds a case payload to CreatedCases.
func (m *MockSalesforceClientImpl) SendCase(payload email.Case) error {
	m.Lock()
	defer m.Unlock()

	m.CreatedCases = append(m.CreatedCases, payload)
	return nil
}

// GetCreatedCases is used for testing to retrieve the list of created cases in
// a thread-safe manner.
func (m *MockSalesforceClientImpl) GetCreatedCases() []email.Case {
	m.Lock()
	defer m.Unlock()

	// Return a copy to avoid race conditions.
	return slices.Clone(m.CreatedCases)
}

var _ emailpb.ExporterClient = (*MockExporterClientImpl)(nil)

// MockExporterClientImpl is a mock implementation of ExporterClient.
type MockExporterClientImpl struct {
	SalesforceClient email.SalesforceClient
}

// NewMockExporterImpl returns a MockExporterClientImpl as an ExporterClient.
func NewMockExporterImpl(salesforceClient email.SalesforceClient) emailpb.ExporterClient {
	return &MockExporterClientImpl{
		SalesforceClient: salesforceClient,
	}
}

// SendContacts submits emails to the inner email.SalesforceClient, returning an
// error if any fail.
func (m *MockExporterClientImpl) SendContacts(ctx context.Context, req *emailpb.SendContactsRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	for _, e := range req.Emails {
		err := m.SalesforceClient.SendContact(e)
		if err != nil {
			return nil, err
		}
	}
	return &emptypb.Empty{}, nil
}

// SendCase submits a Case using the inner email.SalesforceClient.
func (m *MockExporterClientImpl) SendCase(ctx context.Context, req *emailpb.SendCaseRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, m.SalesforceClient.SendCase(email.Case{
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
}
