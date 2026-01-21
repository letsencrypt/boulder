package bdns

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
)

// MockClient is a mock
type MockClient struct{}

// LookupTXT is a mock
func (mock *MockClient) LookupTXT(_ context.Context, hostname string) (*Result[*dns.TXT], string, error) {
	return nil, "MockClient", fmt.Errorf("unexpected LookupTXT call on test fake")
}

// LookupA is a fake
func (mock *MockClient) LookupA(_ context.Context, hostname string) (*Result[*dns.A], string, error) {
	return nil, "MockClient", fmt.Errorf("unexpected LookupA call on test fake")
}

// LookupAAAA is a fake
func (mock *MockClient) LookupAAAA(_ context.Context, hostname string) (*Result[*dns.AAAA], string, error) {
	return nil, "MockClient", fmt.Errorf("unexpected LookupAAAA call on test fake")
}

// LookupCAA is a fake
func (mock *MockClient) LookupCAA(_ context.Context, domain string) (*Result[*dns.CAA], string, error) {
	return nil, "MockClient", fmt.Errorf("unexpected LookupCAA call on test fake")
}
