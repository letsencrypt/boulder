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
	f := false
	return &sapb.Exists{
		Exists: &f,
	}, nil
}

func (sa *mockInvalidAuthorizationsAuthority) CountInvalidAuthorizations2(ctx context.Context, req *sapb.CountInvalidAuthorizationsRequest) (*sapb.Count, error) {
	var count int64
	if *req.Hostname == sa.domainWithFailures {
		count = 1
	}
	return &sapb.Count{
		Count: &count,
	}, nil
}
