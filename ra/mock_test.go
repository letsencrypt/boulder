package ra

import (
	"context"

	"github.com/letsencrypt/boulder/mocks"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type mockInvalidAuthorizationsAuthority struct {
	mocks.StorageAuthority
	domainWithFailures string
}

func (sa *mockInvalidAuthorizationsAuthority) CountOrders(ctx context.Context, _ *sapb.CountOrdersRequest) (*sapb.Count, error) {
	return &sapb.Count{}, nil
}

func (sa *mockInvalidAuthorizationsAuthority) PreviousCertificateExists(
	_ context.Context,
	_ *sapb.PreviousCertificateExistsRequest,
) (*sapb.Exists, error) {
	return &sapb.Exists{
		Exists: false,
	}, nil
}

func (sa *mockInvalidAuthorizationsAuthority) CountInvalidAuthorizations2(ctx context.Context, req *sapb.CountInvalidAuthorizationsRequest) (*sapb.Count, error) {
	if req.Hostname == sa.domainWithFailures {
		return &sapb.Count{Count: 1}, nil
	} else {
		return &sapb.Count{}, nil
	}
}
