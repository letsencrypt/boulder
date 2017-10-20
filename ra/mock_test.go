package ra

import (
	"context"

	"google.golang.org/grpc"

	core "github.com/letsencrypt/boulder/core/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

var (
	_ sapb.StorageAuthorityClient = &mockInvalidAuthorizationsAuthority{}
)

type mockInvalidAuthorizationsAuthority struct {
}

func (sa *mockInvalidAuthorizationsAuthority) GetRegistration(ctx context.Context, in *sapb.RegistrationID, opts ...grpc.CallOption) (*core.Registration, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetRegistrationByKey(ctx context.Context, in *sapb.JSONWebKey, opts ...grpc.CallOption) (*core.Registration, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetAuthorization(ctx context.Context, in *sapb.AuthorizationID, opts ...grpc.CallOption) (*core.Authorization, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetPendingAuthorization(ctx context.Context, in *sapb.GetPendingAuthorizationRequest, opts ...grpc.CallOption) (*core.Authorization, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetValidAuthorizations(ctx context.Context, in *sapb.GetValidAuthorizationsRequest, opts ...grpc.CallOption) (*sapb.ValidAuthorizations, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetCertificate(ctx context.Context, in *sapb.Serial, opts ...grpc.CallOption) (*core.Certificate, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetCertificateStatus(ctx context.Context, in *sapb.Serial, opts ...grpc.CallOption) (*sapb.CertificateStatus, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) CountCertificatesRange(ctx context.Context, in *sapb.Range, opts ...grpc.CallOption) (*sapb.Count, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) CountCertificatesByNames(ctx context.Context, in *sapb.CountCertificatesByNamesRequest, opts ...grpc.CallOption) (*sapb.CountByNames, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) CountCertificatesByExactNames(ctx context.Context, in *sapb.CountCertificatesByNamesRequest, opts ...grpc.CallOption) (*sapb.CountByNames, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) CountRegistrationsByIP(ctx context.Context, in *sapb.CountRegistrationsByIPRequest, opts ...grpc.CallOption) (*sapb.Count, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) CountRegistrationsByIPRange(ctx context.Context, in *sapb.CountRegistrationsByIPRequest, opts ...grpc.CallOption) (*sapb.Count, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) CountPendingAuthorizations(ctx context.Context, in *sapb.RegistrationID, opts ...grpc.CallOption) (*sapb.Count, error) {
	return &sapb.Count{
		Count: new(int64),
	}, nil
}

func (sa *mockInvalidAuthorizationsAuthority) CountInvalidAuthorizations(ctx context.Context, in *sapb.CountInvalidAuthorizationsRequest, opts ...grpc.CallOption) (*sapb.Count, error) {
	count := int64(1)
	return &sapb.Count{
		Count: &count,
	}, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetSCTReceipt(ctx context.Context, in *sapb.GetSCTReceiptRequest, opts ...grpc.CallOption) (*sapb.SignedCertificateTimestamp, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) CountFQDNSets(ctx context.Context, in *sapb.CountFQDNSetsRequest, opts ...grpc.CallOption) (*sapb.Count, error) {
	return nil, nil
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

func (sa *mockInvalidAuthorizationsAuthority) NewPendingAuthorization(ctx context.Context, in *core.Authorization, opts ...grpc.CallOption) (*core.Authorization, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) UpdatePendingAuthorization(ctx context.Context, in *core.Authorization, opts ...grpc.CallOption) (*core.Empty, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) FinalizeAuthorization(ctx context.Context, in *core.Authorization, opts ...grpc.CallOption) (*core.Empty, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) MarkCertificateRevoked(ctx context.Context, in *sapb.MarkCertificateRevokedRequest, opts ...grpc.CallOption) (*core.Empty, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) AddCertificate(ctx context.Context, in *sapb.AddCertificateRequest, opts ...grpc.CallOption) (*sapb.AddCertificateResponse, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) AddSCTReceipt(ctx context.Context, in *sapb.SignedCertificateTimestamp, opts ...grpc.CallOption) (*core.Empty, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) RevokeAuthorizationsByDomain(ctx context.Context, in *sapb.RevokeAuthorizationsByDomainRequest, opts ...grpc.CallOption) (*sapb.RevokeAuthorizationsByDomainResponse, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) DeactivateRegistration(ctx context.Context, in *sapb.RegistrationID, opts ...grpc.CallOption) (*core.Empty, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) DeactivateAuthorization(ctx context.Context, in *sapb.AuthorizationID, opts ...grpc.CallOption) (*core.Empty, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) NewOrder(ctx context.Context, in *core.Order, opts ...grpc.CallOption) (*core.Order, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetOrder(ctx context.Context, in *sapb.OrderRequest, opts ...grpc.CallOption) (*core.Order, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetAuthorizations(ctx context.Context, in *sapb.GetAuthorizationsRequest, opts ...grpc.CallOption) (*sapb.Authorizations, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) AddPendingAuthorizations(ctx context.Context, in *sapb.AddPendingAuthorizationsRequest, opts ...grpc.CallOption) (*sapb.AuthorizationIDs, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) GetOrderAuthorizations(ctx context.Context, in *sapb.GetOrderAuthorizationsRequest, opts ...grpc.CallOption) (*sapb.Authorizations, error) {
	return nil, nil
}

func (sa *mockInvalidAuthorizationsAuthority) FinalizeOrder(ctx context.Context, in *core.Order, opts ...grpc.CallOption) (*core.Order, error) {
	return nil, nil
}
