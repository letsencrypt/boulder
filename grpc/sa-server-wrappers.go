package grpc

import (
	"context"
	"net"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto2"
)

// storageGetter are the Boulder SA's read-only methods
type storageGetter interface {
	GetRegistration(ctx context.Context, regID int64) (core.Registration, error)
	GetRegistrationByKey(ctx context.Context, jwk *jose.JSONWebKey) (core.Registration, error)
	GetCertificate(ctx context.Context, serial string) (core.Certificate, error)
	GetPrecertificate(ctx context.Context, req *sapb.Serial) (*corepb.Certificate, error)
	GetCertificateStatus(ctx context.Context, serial string) (core.CertificateStatus, error)
	CountCertificatesByNames(ctx context.Context, domains []string, earliest, latest time.Time) (countByDomain []*sapb.CountByNames_MapElement, err error)
	CountRegistrationsByIP(ctx context.Context, ip net.IP, earliest, latest time.Time) (int, error)
	CountRegistrationsByIPRange(ctx context.Context, ip net.IP, earliest, latest time.Time) (int, error)
	CountOrders(ctx context.Context, acctID int64, earliest, latest time.Time) (int, error)
	CountFQDNSets(ctx context.Context, window time.Duration, domains []string) (count int64, err error)
	FQDNSetExists(ctx context.Context, domains []string) (exists bool, err error)
	PreviousCertificateExists(ctx context.Context, req *sapb.PreviousCertificateExistsRequest) (exists *sapb.Exists, err error)
	GetOrder(ctx context.Context, req *sapb.OrderRequest) (*corepb.Order, error)
	GetOrderForNames(ctx context.Context, req *sapb.GetOrderForNamesRequest) (*corepb.Order, error)
	// New authz2 methods
	GetAuthorization2(ctx context.Context, req *sapb.AuthorizationID2) (*corepb.Authorization, error)
	GetAuthorizations2(ctx context.Context, req *sapb.GetAuthorizationsRequest) (*sapb.Authorizations, error)
	GetPendingAuthorization2(ctx context.Context, req *sapb.GetPendingAuthorizationRequest) (*corepb.Authorization, error)
	CountPendingAuthorizations2(ctx context.Context, req *sapb.RegistrationID) (*sapb.Count, error)
	GetValidOrderAuthorizations2(ctx context.Context, req *sapb.GetValidOrderAuthorizationsRequest) (*sapb.Authorizations, error)
	CountInvalidAuthorizations2(ctx context.Context, req *sapb.CountInvalidAuthorizationsRequest) (*sapb.Count, error)
	GetValidAuthorizations2(ctx context.Context, req *sapb.GetValidAuthorizationsRequest) (*sapb.Authorizations, error)
	KeyBlocked(ctx context.Context, req *sapb.KeyBlockedRequest) (*sapb.Exists, error)
}

// storageAdder are the Boulder SA's write/update methods
type storageAdder interface {
	NewRegistration(ctx context.Context, reg core.Registration) (created core.Registration, err error)
	UpdateRegistration(ctx context.Context, reg core.Registration) error
	AddCertificate(ctx context.Context, der []byte, regID int64, ocsp []byte, issued *time.Time) (digest string, err error)
	AddPrecertificate(ctx context.Context, req *sapb.AddCertificateRequest) (*corepb.Empty, error)
	AddSerial(ctx context.Context, req *sapb.AddSerialRequest) (*corepb.Empty, error)
	DeactivateRegistration(ctx context.Context, id int64) error
	NewOrder(ctx context.Context, order *corepb.Order) (*corepb.Order, error)
	SetOrderProcessing(ctx context.Context, order *corepb.Order) error
	FinalizeOrder(ctx context.Context, order *corepb.Order) error
	SetOrderError(ctx context.Context, order *corepb.Order) error
	RevokeCertificate(ctx context.Context, req *sapb.RevokeCertificateRequest) error
	// New authz2 methods
	NewAuthorizations2(ctx context.Context, req *sapb.AddPendingAuthorizationsRequest) (*sapb.Authorization2IDs, error)
	FinalizeAuthorization2(ctx context.Context, req *sapb.FinalizeAuthorizationRequest) error
	DeactivateAuthorization2(ctx context.Context, req *sapb.AuthorizationID2) (*corepb.Empty, error)
	AddBlockedKey(ctx context.Context, req *sapb.AddBlockedKeyRequest) (*corepb.Empty, error)
}

// storageAuthority interface represents a simple key/value
// store. The add and get interfaces contained within are divided
// for privilege separation.
type storageAuthority interface {
	storageGetter
	storageAdder
}

// StorageAuthorityServerWrapper is the gRPC version of a core.ServerAuthority server
type StorageAuthorityServerWrapper struct {
	// TODO(#3119): Don't use core.StorageAuthority
	inner storageAuthority
	storageAuthority
}

func NewStorageAuthorityServer(inner storageAuthority) *StorageAuthorityServerWrapper {
	return &StorageAuthorityServerWrapper{inner, inner}
}

func (sas StorageAuthorityServerWrapper) GetRegistration(ctx context.Context, request *sapb.RegistrationID) (*corepb.Registration, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	reg, err := sas.inner.GetRegistration(ctx, *request.Id)
	if err != nil {
		return nil, err
	}

	return registrationToPB(reg)
}

func (sas StorageAuthorityServerWrapper) GetRegistrationByKey(ctx context.Context, request *sapb.JSONWebKey) (*corepb.Registration, error) {
	if request == nil || request.Jwk == nil {
		return nil, errIncompleteRequest
	}

	var jwk jose.JSONWebKey
	err := jwk.UnmarshalJSON(request.Jwk)
	if err != nil {
		return nil, err
	}

	reg, err := sas.inner.GetRegistrationByKey(ctx, &jwk)
	if err != nil {
		return nil, err
	}

	return registrationToPB(reg)
}

func (sas StorageAuthorityServerWrapper) GetCertificate(ctx context.Context, request *sapb.Serial) (*corepb.Certificate, error) {
	if request == nil || request.Serial == nil {
		return nil, errIncompleteRequest
	}

	cert, err := sas.inner.GetCertificate(ctx, *request.Serial)
	if err != nil {
		return nil, err
	}

	return CertToPB(cert), nil
}

func (sas StorageAuthorityServerWrapper) GetPrecertificate(ctx context.Context, request *sapb.Serial) (*corepb.Certificate, error) {
	if request == nil || request.Serial == nil {
		return nil, errIncompleteRequest
	}
	return sas.inner.GetPrecertificate(ctx, request)
}

func (sas StorageAuthorityServerWrapper) GetCertificateStatus(ctx context.Context, request *sapb.Serial) (*corepb.CertificateStatus, error) {
	if request == nil || request.Serial == nil {
		return nil, errIncompleteRequest
	}

	certStatus, err := sas.inner.GetCertificateStatus(ctx, *request.Serial)
	if err != nil {
		return nil, err
	}

	return CertStatusToPB(certStatus), nil
}

func (sas StorageAuthorityServerWrapper) CountCertificatesByNames(ctx context.Context, request *sapb.CountCertificatesByNamesRequest) (*sapb.CountByNames, error) {
	if request == nil || request.Range == nil || request.Range.Earliest == nil || request.Range.Latest == nil || request.Names == nil {
		return nil, errIncompleteRequest
	}

	byNames, err := sas.inner.CountCertificatesByNames(ctx, request.Names, time.Unix(0, *request.Range.Earliest), time.Unix(0, *request.Range.Latest))
	if err != nil {
		return nil, err
	}

	return &sapb.CountByNames{CountByNames: byNames}, nil
}

func (sas StorageAuthorityServerWrapper) CountRegistrationsByIP(ctx context.Context, request *sapb.CountRegistrationsByIPRequest) (*sapb.Count, error) {
	if request == nil || request.Ip == nil || request.Range == nil || request.Range.Earliest == nil || request.Range.Latest == nil {
		return nil, errIncompleteRequest
	}

	count, err := sas.inner.CountRegistrationsByIP(
		ctx,
		net.IP(request.Ip),
		time.Unix(0, *request.Range.Earliest),
		time.Unix(0, *request.Range.Latest))
	if err != nil {
		return nil, err
	}

	castedCount := int64(count)
	return &sapb.Count{Count: &castedCount}, nil
}

func (sas StorageAuthorityServerWrapper) CountRegistrationsByIPRange(ctx context.Context, request *sapb.CountRegistrationsByIPRequest) (*sapb.Count, error) {
	if request == nil || request.Ip == nil || request.Range == nil || request.Range.Earliest == nil || request.Range.Latest == nil {
		return nil, errIncompleteRequest
	}

	count, err := sas.inner.CountRegistrationsByIPRange(
		ctx,
		net.IP(request.Ip),
		time.Unix(0, *request.Range.Earliest),
		time.Unix(0, *request.Range.Latest))
	if err != nil {
		return nil, err
	}

	castedCount := int64(count)
	return &sapb.Count{Count: &castedCount}, nil
}

func (sas StorageAuthorityServerWrapper) CountOrders(ctx context.Context, request *sapb.CountOrdersRequest) (*sapb.Count, error) {
	if request == nil || request.AccountID == nil || request.Range == nil || request.Range.Earliest == nil || request.Range.Latest == nil {
		return nil, errIncompleteRequest
	}

	count, err := sas.inner.CountOrders(ctx,
		*request.AccountID,
		time.Unix(0, *request.Range.Earliest),
		time.Unix(0, *request.Range.Latest),
	)
	if err != nil {
		return nil, err
	}

	castedCount := int64(count)
	return &sapb.Count{Count: &castedCount}, nil
}

func (sas StorageAuthorityServerWrapper) CountFQDNSets(ctx context.Context, request *sapb.CountFQDNSetsRequest) (*sapb.Count, error) {
	if request == nil || request.Window == nil || request.Domains == nil {
		return nil, errIncompleteRequest
	}

	window := time.Duration(*request.Window)

	count, err := sas.inner.CountFQDNSets(ctx, window, request.Domains)
	if err != nil {
		return nil, err
	}

	castedCount := int64(count)
	return &sapb.Count{Count: &castedCount}, nil
}

func (sas StorageAuthorityServerWrapper) FQDNSetExists(ctx context.Context, request *sapb.FQDNSetExistsRequest) (*sapb.Exists, error) {
	if request == nil || request.Domains == nil {
		return nil, errIncompleteRequest
	}

	exists, err := sas.inner.FQDNSetExists(ctx, request.Domains)
	if err != nil {
		return nil, err
	}

	return &sapb.Exists{Exists: &exists}, nil
}

func (sac StorageAuthorityServerWrapper) PreviousCertificateExists(
	ctx context.Context,
	req *sapb.PreviousCertificateExistsRequest,
) (*sapb.Exists, error) {
	if req == nil || req.Domain == nil || req.RegID == nil {
		return nil, errIncompleteRequest
	}
	return sac.inner.PreviousCertificateExists(ctx, req)
}

func (sas StorageAuthorityServerWrapper) NewRegistration(ctx context.Context, request *corepb.Registration) (*corepb.Registration, error) {
	if request == nil || !registrationValid(request) {
		return nil, errIncompleteRequest
	}

	reg, err := pbToRegistration(request)
	if err != nil {
		return nil, err
	}

	newReg, err := sas.inner.NewRegistration(ctx, reg)
	if err != nil {
		return nil, err
	}

	return registrationToPB(newReg)
}

func (sas StorageAuthorityServerWrapper) UpdateRegistration(ctx context.Context, request *corepb.Registration) (*corepb.Empty, error) {
	if request == nil || !registrationValid(request) {
		return nil, errIncompleteRequest
	}

	reg, err := pbToRegistration(request)
	if err != nil {
		return nil, err
	}

	err = sas.inner.UpdateRegistration(ctx, reg)
	if err != nil {
		return nil, err
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) AddCertificate(ctx context.Context, request *sapb.AddCertificateRequest) (*sapb.AddCertificateResponse, error) {
	if request == nil || request.Der == nil || request.RegID == nil || request.Issued == nil {
		return nil, errIncompleteRequest
	}

	reqIssued := time.Unix(0, *request.Issued)
	digest, err := sas.inner.AddCertificate(ctx, request.Der, *request.RegID, request.Ocsp, &reqIssued)
	if err != nil {
		return nil, err
	}

	return &sapb.AddCertificateResponse{Digest: &digest}, nil
}

func (sas StorageAuthorityServerWrapper) DeactivateRegistration(ctx context.Context, request *sapb.RegistrationID) (*corepb.Empty, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	err := sas.inner.DeactivateRegistration(ctx, *request.Id)
	if err != nil {
		return nil, err
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) NewOrder(ctx context.Context, request *corepb.Order) (*corepb.Order, error) {
	if request == nil || !newOrderValid(request) {
		return nil, errIncompleteRequest
	}

	return sas.inner.NewOrder(ctx, request)
}

func (sas StorageAuthorityServerWrapper) SetOrderProcessing(ctx context.Context, order *corepb.Order) (*corepb.Empty, error) {
	if order == nil || !orderValid(order) {
		return nil, errIncompleteRequest
	}

	if err := sas.inner.SetOrderProcessing(ctx, order); err != nil {
		return nil, err
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) SetOrderError(ctx context.Context, order *corepb.Order) (*corepb.Empty, error) {
	if order == nil || !orderValid(order) {
		return nil, errIncompleteRequest
	}

	if err := sas.inner.SetOrderError(ctx, order); err != nil {
		return nil, err
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) FinalizeOrder(ctx context.Context, order *corepb.Order) (*corepb.Empty, error) {
	if order == nil || !orderValid(order) || order.CertificateSerial == nil {
		return nil, errIncompleteRequest
	}

	if err := sas.inner.FinalizeOrder(ctx, order); err != nil {
		return nil, err
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) GetOrder(ctx context.Context, request *sapb.OrderRequest) (*corepb.Order, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.GetOrder(ctx, request)
}

func (sas StorageAuthorityServerWrapper) GetOrderForNames(
	ctx context.Context,
	request *sapb.GetOrderForNamesRequest) (*corepb.Order, error) {
	if request == nil || request.AcctID == nil || len(request.Names) == 0 {
		return nil, errIncompleteRequest
	}
	return sas.inner.GetOrderForNames(ctx, request)
}

func (sas StorageAuthorityServerWrapper) GetAuthorization2(ctx context.Context, request *sapb.AuthorizationID2) (*corepb.Authorization, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.GetAuthorization2(ctx, request)
}

func (sas StorageAuthorityServerWrapper) RevokeCertificate(ctx context.Context, req *sapb.RevokeCertificateRequest) (*corepb.Empty, error) {
	if req == nil || req.Serial == nil || req.Reason == nil || req.Date == nil || req.Response == nil {
		return nil, errIncompleteRequest
	}
	return &corepb.Empty{}, sas.inner.RevokeCertificate(ctx, req)
}

func (sas StorageAuthorityServerWrapper) NewAuthorizations2(ctx context.Context, req *sapb.AddPendingAuthorizationsRequest) (*sapb.Authorization2IDs, error) {
	if req == nil || req.Authz == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.NewAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) GetAuthorizations2(ctx context.Context, req *sapb.GetAuthorizationsRequest) (*sapb.Authorizations, error) {
	if req == nil || req.Domains == nil || req.RegistrationID == nil || req.Now == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.GetAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) FinalizeAuthorization2(ctx context.Context, req *sapb.FinalizeAuthorizationRequest) (*corepb.Empty, error) {
	if req == nil || req.Status == nil || req.Attempted == nil || req.Expires == nil || req.Id == nil {
		return nil, errIncompleteRequest
	}

	return &corepb.Empty{}, sas.inner.FinalizeAuthorization2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) GetPendingAuthorization2(ctx context.Context, req *sapb.GetPendingAuthorizationRequest) (*corepb.Authorization, error) {
	if req == nil || req.RegistrationID == nil || req.IdentifierValue == nil || req.ValidUntil == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.GetPendingAuthorization2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) CountPendingAuthorizations2(ctx context.Context, req *sapb.RegistrationID) (*sapb.Count, error) {
	if req == nil || req.Id == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.CountPendingAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) GetValidOrderAuthorizations2(ctx context.Context, req *sapb.GetValidOrderAuthorizationsRequest) (*sapb.Authorizations, error) {
	if req == nil || req.AcctID == nil || req.Id == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.GetValidOrderAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) CountInvalidAuthorizations2(ctx context.Context, req *sapb.CountInvalidAuthorizationsRequest) (*sapb.Count, error) {
	if req == nil || req.RegistrationID == nil || req.Hostname == nil || req.Range == nil || req.Range.Earliest == nil || req.Range.Latest == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.CountInvalidAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) GetValidAuthorizations2(ctx context.Context, req *sapb.GetValidAuthorizationsRequest) (*sapb.Authorizations, error) {
	if req == nil || req.Domains == nil || req.RegistrationID == nil || req.Now == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.GetValidAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) DeactivateAuthorization2(ctx context.Context, req *sapb.AuthorizationID2) (*corepb.Empty, error) {
	if req == nil || req.Id == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.DeactivateAuthorization2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) AddBlockedKey(ctx context.Context, req *sapb.AddBlockedKeyRequest) (*corepb.Empty, error) {
	// All request checking is done in the method
	return sas.inner.AddBlockedKey(ctx, req)
}

func (sas StorageAuthorityServerWrapper) KeyBlocked(ctx context.Context, req *sapb.KeyBlockedRequest) (*sapb.Exists, error) {
	// All request checking is done in the method
	return sas.inner.KeyBlocked(ctx, req)
}
