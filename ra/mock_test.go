package ra

import (
	"context"
	"time"

	"github.com/letsencrypt/boulder/mocks"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type mockInvalidAuthorizationsAuthority struct {
	mocks.StorageAuthority
	domainWithFailures string
}

func (sa *mockInvalidAuthorizationsAuthority) CountOrders(ctx context.Context, _ int64, _ time.Time, _ time.Time) (int, error) {
	return 0, nil
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
