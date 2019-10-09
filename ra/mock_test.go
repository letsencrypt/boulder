package ra

import (
	"context"

	"google.golang.org/grpc"

	core "github.com/letsencrypt/boulder/core/proto"
	corepb "github.com/letsencrypt/boulder/core/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

var (
	_ sapb.StorageAuthorityClient = &mockInvalidAuthorizationsAuthority{}
)

type mockInvalidAuthorizationsAuthority struct {
	domainWithFailures string
}

func (sa *mockInvalidAuthorizationsAuthority) GetRegistration(ctx context.Context, in *sapb.RegistrationID, opts ...grpc.CallOption) (*core.Registration, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetRegistrationByKey(ctx context.Context, in *sapb.JSONWebKey, opts ...grpc.CallOption) (*core.Registration, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetCertificate(ctx context.Context, in *sapb.Serial, opts ...grpc.CallOption) (*core.Certificate, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetPrecertificate(_ context.Context, _ *sapb.Serial, opts ...grpc.CallOption) (*core.Certificate, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetCertificateStatus(ctx context.Context, in *sapb.Serial, opts ...grpc.CallOption) (*sapb.CertificateStatus, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) CountCertificatesByNames(ctx context.Context, in *sapb.CountCertificatesByNamesRequest, opts ...grpc.CallOption) (*sapb.CountByNames, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) CountRegistrationsByIP(ctx context.Context, in *sapb.CountRegistrationsByIPRequest, opts ...grpc.CallOption) (*sapb.Count, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) CountRegistrationsByIPRange(ctx context.Context, in *sapb.CountRegistrationsByIPRequest, opts ...grpc.CallOption) (*sapb.Count, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) CountOrders(ctx context.Context, in *sapb.CountOrdersRequest, opts ...grpc.CallOption) (*sapb.Count, error) {
	return &sapb.Count{
		Count: new(int64),
	}, nil
}

func (sa *mockInvalidAuthorizationsAuthority) CountFQDNSets(ctx context.Context, in *sapb.CountFQDNSetsRequest, opts ...grpc.CallOption) (*sapb.Count, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) PreviousCertificateExists(
	_ context.Context,
	_ *sapb.PreviousCertificateExistsRequest,
	_ ...grpc.CallOption,
) (*sapb.Exists, error) {
	f := false
	return &sapb.Exists{
		Exists: &f,
	}, nil
}

func (sa *mockInvalidAuthorizationsAuthority) FQDNSetExists(ctx context.Context, in *sapb.FQDNSetExistsRequest, opts ...grpc.CallOption) (*sapb.Exists, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) NewRegistration(ctx context.Context, in *core.Registration, opts ...grpc.CallOption) (*core.Registration, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) UpdateRegistration(ctx context.Context, in *core.Registration, opts ...grpc.CallOption) (*core.Empty, error) {
	return nil, nil
}

// AddPrecertificate is a mock
func (sa *mockInvalidAuthorizationsAuthority) AddPrecertificate(ctx context.Context, req *sapb.AddCertificateRequest, opts ...grpc.CallOption) (empty *corepb.Empty, err error) {
	return
}

// AddSerial is a mock
func (sa *mockInvalidAuthorizationsAuthority) AddSerial(ctx context.Context, req *sapb.AddSerialRequest, opts ...grpc.CallOption) (empty *corepb.Empty, err error) {
	return
}

func (sa *mockInvalidAuthorizationsAuthority) AddCertificate(ctx context.Context, in *sapb.AddCertificateRequest, opts ...grpc.CallOption) (*sapb.AddCertificateResponse, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) DeactivateRegistration(ctx context.Context, in *sapb.RegistrationID, opts ...grpc.CallOption) (*core.Empty, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) NewOrder(ctx context.Context, in *core.Order, opts ...grpc.CallOption) (*core.Order, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetOrder(ctx context.Context, in *sapb.OrderRequest, opts ...grpc.CallOption) (*core.Order, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetOrderForNames(ctx context.Context, in *sapb.GetOrderForNamesRequest, opts ...grpc.CallOption) (*core.Order, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) SetOrderProcessing(ctx context.Context, in *core.Order, opts ...grpc.CallOption) (*core.Empty, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) SetOrderError(ctx context.Context, in *core.Order, opts ...grpc.CallOption) (*core.Empty, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) FinalizeOrder(ctx context.Context, in *core.Order, opts ...grpc.CallOption) (*core.Empty, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) RevokeCertificate(_ context.Context, _ *sapb.RevokeCertificateRequest, opts ...grpc.CallOption) (*core.Empty, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetAuthorization2(_ context.Context, _ *sapb.AuthorizationID2, opts ...grpc.CallOption) (*corepb.Authorization, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) NewAuthorizations2(ctx context.Context, req *sapb.AddPendingAuthorizationsRequest, opts ...grpc.CallOption) (*sapb.Authorization2IDs, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) FinalizeAuthorization2(ctx context.Context, req *sapb.FinalizeAuthorizationRequest, opts ...grpc.CallOption) (*corepb.Empty, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) DeactivateAuthorization2(ctx context.Context, req *sapb.AuthorizationID2, opts ...grpc.CallOption) (*corepb.Empty, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) CountPendingAuthorizations2(ctx context.Context, req *sapb.RegistrationID, opts ...grpc.CallOption) (*sapb.Count, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetValidOrderAuthorizations2(ctx context.Context, req *sapb.GetValidOrderAuthorizationsRequest, opts ...grpc.CallOption) (*sapb.Authorizations, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) CountInvalidAuthorizations2(ctx context.Context, req *sapb.CountInvalidAuthorizationsRequest, opts ...grpc.CallOption) (*sapb.Count, error) {
	var count int64
	if *req.Hostname == sa.domainWithFailures {
		count = 1
	}
	return &sapb.Count{
		Count: &count,
	}, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetValidAuthorizations2(ctx context.Context, req *sapb.GetValidAuthorizationsRequest, opts ...grpc.CallOption) (*sapb.Authorizations, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetAuthorizations2(ctx context.Context, req *sapb.GetAuthorizationsRequest, opts ...grpc.CallOption) (*sapb.Authorizations, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetPendingAuthorization2(ctx context.Context, req *sapb.GetPendingAuthorizationRequest, opts ...grpc.CallOption) (*corepb.Authorization, error) {
	return nil, nil
}
