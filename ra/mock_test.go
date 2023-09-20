package ra

import (
	"context"
	"time"

	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/mocks"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mockInvalidAuthorizationsAuthority struct {
	mocks.StorageAuthority
	domainWithFailures string
}

// SetCertificateStatusReady implements proto.StorageAuthorityClient
func (*mockInvalidAuthorizationsAuthority) SetCertificateStatusReady(ctx context.Context, in *sapb.Serial, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented mock")
}

func (sa *mockInvalidAuthorizationsAuthority) CountOrders(_ context.Context, _ *sapb.CountOrdersRequest, _ ...grpc.CallOption) (*sapb.Count, error) {
	return &sapb.Count{}, nil
}

func (sa *mockInvalidAuthorizationsAuthority) PreviousCertificateExists(_ context.Context, _ *sapb.PreviousCertificateExistsRequest, _ ...grpc.CallOption) (*sapb.Exists, error) {
	return &sapb.Exists{
		Exists: false,
	}, nil
}

func (sa *mockInvalidAuthorizationsAuthority) CountInvalidAuthorizations2(ctx context.Context, req *sapb.CountInvalidAuthorizationsRequest, _ ...grpc.CallOption) (*sapb.Count, error) {
	if req.Hostname == sa.domainWithFailures {
		return &sapb.Count{Count: 1}, nil
	} else {
		return &sapb.Count{}, nil
	}
}

// An authority that returns nonzero failures for CountInvalidAuthorizations2,
// and also returns existing authzs for the same domain from GetAuthorizations2
type mockInvalidPlusValidAuthzAuthority struct {
	mockInvalidAuthorizationsAuthority
}

func (sa *mockInvalidPlusValidAuthzAuthority) GetAuthorizations2(ctx context.Context, req *sapb.GetAuthorizationsRequest, _ ...grpc.CallOption) (*sapb.Authorizations, error) {
	date := time.Date(2101, 12, 3, 0, 0, 0, 0, time.UTC)

	return &sapb.Authorizations{
		Authz: []*sapb.Authorizations_MapElement{
			{
				Domain: sa.domainWithFailures, Authz: &corepb.Authorization{
					Id:             "1234",
					Status:         "valid",
					Identifier:     sa.domainWithFailures,
					RegistrationID: 1234,
					ExpiresNS:      date.Unix(),
					Expires:        timestamppb.New(date),
				},
			},
		},
	}, nil
}
