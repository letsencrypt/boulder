// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wrappers wraps the GRPC calls in the core interfaces.
package grpc

import (
	"context"
	"net"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

// StorageAuthorityClientWrapper is the gRPC version of a core.StorageAuthority client
type StorageAuthorityClientWrapper struct {
	inner sapb.StorageAuthorityClient
}

func NewStorageAuthorityClient(inner sapb.StorageAuthorityClient) *StorageAuthorityClientWrapper {
	return &StorageAuthorityClientWrapper{inner}
}

func (sac StorageAuthorityClientWrapper) GetRegistration(ctx context.Context, req *sapb.RegistrationID) (*corepb.Registration, error) {
	return sac.inner.GetRegistration(ctx, req)
}

func (sac StorageAuthorityClientWrapper) GetRegistrationByKey(ctx context.Context, req *sapb.JSONWebKey) (*corepb.Registration, error) {
	return sac.inner.GetRegistrationByKey(ctx, req)
}

func (sac StorageAuthorityClientWrapper) GetCertificate(ctx context.Context, req *sapb.Serial) (*corepb.Certificate, error) {
	return sac.inner.GetCertificate(ctx, req)
}

func (sac StorageAuthorityClientWrapper) GetPrecertificate(ctx context.Context, serial *sapb.Serial) (*corepb.Certificate, error) {
	return sac.inner.GetPrecertificate(ctx, serial)
}

func (sac StorageAuthorityClientWrapper) GetCertificateStatus(ctx context.Context, serial string) (core.CertificateStatus, error) {
	response, err := sac.inner.GetCertificateStatus(ctx, &sapb.Serial{Serial: serial})
	if err != nil {
		return core.CertificateStatus{}, err
	}
	if response == nil || response.Serial == "" || response.Status == "" || response.OcspLastUpdated == 0 || response.LastExpirationNagSent == 0 || response.OcspResponse == nil || response.NotAfter == 0 {
		return core.CertificateStatus{}, errIncompleteResponse
	}
	return PBToCertStatus(response)
}

func (sac StorageAuthorityClientWrapper) CountCertificatesByNames(ctx context.Context, domains []string, earliest, latest time.Time) ([]*sapb.CountByNames_MapElement, error) {
	earliestNano := earliest.UnixNano()
	latestNano := latest.UnixNano()

	response, err := sac.inner.CountCertificatesByNames(ctx, &sapb.CountCertificatesByNamesRequest{
		Names: domains,
		Range: &sapb.Range{
			Earliest: earliestNano,
			Latest:   latestNano,
		},
	})
	if err != nil {
		return nil, err
	}

	if response == nil || response.CountByNames == nil {
		return nil, errIncompleteResponse
	}

	return response.CountByNames, nil
}

func (sac StorageAuthorityClientWrapper) CountRegistrationsByIP(ctx context.Context, ip net.IP, earliest, latest time.Time) (int, error) {
	earliestNano := earliest.UnixNano()
	latestNano := latest.UnixNano()

	response, err := sac.inner.CountRegistrationsByIP(ctx, &sapb.CountRegistrationsByIPRequest{
		Range: &sapb.Range{
			Earliest: earliestNano,
			Latest:   latestNano,
		},
		Ip: ip,
	})
	if err != nil {
		return 0, err
	}

	if response == nil {
		return 0, errIncompleteResponse
	}

	return int(response.Count), nil
}

func (sac StorageAuthorityClientWrapper) CountRegistrationsByIPRange(ctx context.Context, ip net.IP, earliest, latest time.Time) (int, error) {
	earliestNano := earliest.UnixNano()
	latestNano := latest.UnixNano()

	response, err := sac.inner.CountRegistrationsByIPRange(ctx, &sapb.CountRegistrationsByIPRequest{
		Range: &sapb.Range{
			Earliest: earliestNano,
			Latest:   latestNano,
		},
		Ip: ip,
	})
	if err != nil {
		return 0, err
	}

	if response == nil {
		return 0, errIncompleteResponse
	}

	return int(response.Count), nil
}

func (sac StorageAuthorityClientWrapper) CountOrders(ctx context.Context, acctID int64, earliest, latest time.Time) (int, error) {
	earliestNano := earliest.UnixNano()
	latestNano := latest.UnixNano()

	response, err := sac.inner.CountOrders(ctx, &sapb.CountOrdersRequest{
		AccountID: acctID,
		Range: &sapb.Range{
			Earliest: earliestNano,
			Latest:   latestNano,
		},
	})
	if err != nil {
		return 0, err
	}

	if response == nil {
		return 0, errIncompleteResponse
	}

	return int(response.Count), nil
}

func (sac StorageAuthorityClientWrapper) CountFQDNSets(ctx context.Context, window time.Duration, domains []string) (int64, error) {
	windowNanos := window.Nanoseconds()

	response, err := sac.inner.CountFQDNSets(ctx, &sapb.CountFQDNSetsRequest{
		Window:  windowNanos,
		Domains: domains,
	})
	if err != nil {
		return 0, err
	}

	if response == nil {
		return 0, errIncompleteResponse
	}

	return response.Count, nil
}

func (sac StorageAuthorityClientWrapper) PreviousCertificateExists(ctx context.Context, req *sapb.PreviousCertificateExistsRequest) (*sapb.Exists, error) {
	return sac.inner.PreviousCertificateExists(ctx, req)
}

func (sac StorageAuthorityClientWrapper) AddPrecertificate(ctx context.Context, req *sapb.AddCertificateRequest) (*emptypb.Empty, error) {
	return sac.inner.AddPrecertificate(ctx, req)
}

func (sac StorageAuthorityClientWrapper) AddSerial(ctx context.Context, req *sapb.AddSerialRequest) (*emptypb.Empty, error) {
	return sac.inner.AddSerial(ctx, req)
}

func (sac StorageAuthorityClientWrapper) FQDNSetExists(ctx context.Context, req *sapb.FQDNSetExistsRequest) (*sapb.Exists, error) {
	return sac.inner.FQDNSetExists(ctx, req)
}

func (sac StorageAuthorityClientWrapper) NewRegistration(ctx context.Context, req *corepb.Registration) (*corepb.Registration, error) {
	return sac.inner.NewRegistration(ctx, req)
}

func (sac StorageAuthorityClientWrapper) UpdateRegistration(ctx context.Context, req *corepb.Registration) (*emptypb.Empty, error) {
	return sac.inner.UpdateRegistration(ctx, req)
}

func (sac StorageAuthorityClientWrapper) AddCertificate(ctx context.Context, req *sapb.AddCertificateRequest) (*sapb.AddCertificateResponse, error) {
	return sac.inner.AddCertificate(ctx, req)
}

func (sac StorageAuthorityClientWrapper) DeactivateRegistration(ctx context.Context, request *sapb.RegistrationID) (*emptypb.Empty, error) {
	return sac.inner.DeactivateRegistration(ctx, request)
}

func (sas StorageAuthorityClientWrapper) NewOrder(ctx context.Context, request *corepb.Order) (*corepb.Order, error) {
	resp, err := sas.inner.NewOrder(ctx, request)
	if err != nil {
		return nil, err
	}
	if resp == nil || !orderValid(resp) {
		return nil, errIncompleteResponse
	}
	return resp, nil
}

func (sac StorageAuthorityClientWrapper) SetOrderProcessing(ctx context.Context, order *corepb.Order) error {
	if _, err := sac.inner.SetOrderProcessing(ctx, order); err != nil {
		return err
	}
	return nil
}

func (sac StorageAuthorityClientWrapper) SetOrderError(ctx context.Context, order *corepb.Order) error {
	_, err := sac.inner.SetOrderError(ctx, order)
	return err
}

func (sac StorageAuthorityClientWrapper) FinalizeOrder(ctx context.Context, order *corepb.Order) error {
	if _, err := sac.inner.FinalizeOrder(ctx, order); err != nil {
		return err
	}
	return nil
}

func (sas StorageAuthorityClientWrapper) GetOrder(ctx context.Context, request *sapb.OrderRequest) (*corepb.Order, error) {
	return sas.inner.GetOrder(ctx, request)
}

func (sas StorageAuthorityClientWrapper) GetOrderForNames(ctx context.Context, request *sapb.GetOrderForNamesRequest) (*corepb.Order, error) {
	return sas.inner.GetOrderForNames(ctx, request)
}

func (sas StorageAuthorityClientWrapper) GetAuthorization2(ctx context.Context, req *sapb.AuthorizationID2) (*corepb.Authorization, error) {
	return sas.inner.GetAuthorization2(ctx, req)
}

func (sas StorageAuthorityClientWrapper) RevokeCertificate(ctx context.Context, req *sapb.RevokeCertificateRequest) (*emptypb.Empty, error) {
	return sas.inner.RevokeCertificate(ctx, req)
}

func (sas StorageAuthorityClientWrapper) NewAuthorizations2(ctx context.Context, req *sapb.AddPendingAuthorizationsRequest) (*sapb.Authorization2IDs, error) {
	return sas.inner.NewAuthorizations2(ctx, req)
}

func (sas StorageAuthorityClientWrapper) GetAuthorizations2(ctx context.Context, req *sapb.GetAuthorizationsRequest) (*sapb.Authorizations, error) {
	return sas.inner.GetAuthorizations2(ctx, req)
}

func (sas StorageAuthorityClientWrapper) FinalizeAuthorization2(ctx context.Context, req *sapb.FinalizeAuthorizationRequest) (*emptypb.Empty, error) {
	return sas.inner.FinalizeAuthorization2(ctx, req)
}

func (sas StorageAuthorityClientWrapper) GetPendingAuthorization2(ctx context.Context, req *sapb.GetPendingAuthorizationRequest) (*corepb.Authorization, error) {
	return sas.inner.GetPendingAuthorization2(ctx, req)
}

func (sas StorageAuthorityClientWrapper) CountPendingAuthorizations2(ctx context.Context, req *sapb.RegistrationID) (*sapb.Count, error) {
	count, err := sas.inner.CountPendingAuthorizations2(ctx, req)
	if err != nil {
		return nil, err
	}
	if count == nil {
		return nil, errIncompleteResponse
	}
	return count, nil
}

func (sas StorageAuthorityClientWrapper) GetValidOrderAuthorizations2(ctx context.Context, req *sapb.GetValidOrderAuthorizationsRequest) (*sapb.Authorizations, error) {
	return sas.inner.GetValidOrderAuthorizations2(ctx, req)
}

func (sas StorageAuthorityClientWrapper) CountInvalidAuthorizations2(ctx context.Context, req *sapb.CountInvalidAuthorizationsRequest) (*sapb.Count, error) {
	count, err := sas.inner.CountInvalidAuthorizations2(ctx, req)
	if err != nil {
		return nil, err
	}
	if count == nil {
		return nil, errIncompleteResponse
	}
	return count, nil
}

func (sas StorageAuthorityClientWrapper) GetValidAuthorizations2(ctx context.Context, req *sapb.GetValidAuthorizationsRequest) (*sapb.Authorizations, error) {
	return sas.inner.GetValidAuthorizations2(ctx, req)
}

func (sas StorageAuthorityClientWrapper) DeactivateAuthorization2(ctx context.Context, req *sapb.AuthorizationID2) (*emptypb.Empty, error) {
	return sas.inner.DeactivateAuthorization2(ctx, req)
}

func (sac StorageAuthorityClientWrapper) AddBlockedKey(ctx context.Context, req *sapb.AddBlockedKeyRequest) (*emptypb.Empty, error) {
	// All return checking is done at the call site
	return sac.inner.AddBlockedKey(ctx, req)
}

func (sac StorageAuthorityClientWrapper) KeyBlocked(ctx context.Context, req *sapb.KeyBlockedRequest) (*sapb.Exists, error) {
	// All return checking is done at the call site
	return sac.inner.KeyBlocked(ctx, req)
}

// StorageAuthorityServerWrapper is the gRPC version of a core.ServerAuthority server
type StorageAuthorityServerWrapper struct {
	sapb.UnimplementedStorageAuthorityServer
	inner core.StorageAuthority
}

func NewStorageAuthorityServer(inner core.StorageAuthority) *StorageAuthorityServerWrapper {
	return &StorageAuthorityServerWrapper{inner: inner}
}

func (sas *StorageAuthorityServerWrapper) AddPrecertificate(ctx context.Context, req *sapb.AddCertificateRequest) (*emptypb.Empty, error) {
	return sas.inner.AddPrecertificate(ctx, req)
}

func (sas *StorageAuthorityServerWrapper) AddSerial(ctx context.Context, req *sapb.AddSerialRequest) (*emptypb.Empty, error) {
	return sas.inner.AddSerial(ctx, req)
}

func (sas StorageAuthorityServerWrapper) GetRegistration(ctx context.Context, request *sapb.RegistrationID) (*corepb.Registration, error) {
	return sas.inner.GetRegistration(ctx, request)
}

func (sas StorageAuthorityServerWrapper) GetRegistrationByKey(ctx context.Context, request *sapb.JSONWebKey) (*corepb.Registration, error) {
	return sas.inner.GetRegistrationByKey(ctx, request)
}

func (sas StorageAuthorityServerWrapper) GetCertificate(ctx context.Context, request *sapb.Serial) (*corepb.Certificate, error) {
	return sas.inner.GetCertificate(ctx, request)
}

func (sas StorageAuthorityServerWrapper) GetPrecertificate(ctx context.Context, request *sapb.Serial) (*corepb.Certificate, error) {
	return sas.inner.GetPrecertificate(ctx, request)
}

func (sas StorageAuthorityServerWrapper) GetCertificateStatus(ctx context.Context, request *sapb.Serial) (*corepb.CertificateStatus, error) {
	if core.IsAnyNilOrZero(request, request.Serial) {
		return nil, errIncompleteRequest
	}

	certStatus, err := sas.inner.GetCertificateStatus(ctx, request.Serial)
	if err != nil {
		return nil, err
	}

	return CertStatusToPB(certStatus), nil
}

func (sas StorageAuthorityServerWrapper) CountCertificatesByNames(ctx context.Context, request *sapb.CountCertificatesByNamesRequest) (*sapb.CountByNames, error) {
	if core.IsAnyNilOrZero(request, request.Range, request.Range.Earliest, request.Range.Latest, request.Names) {
		return nil, errIncompleteRequest
	}

	byNames, err := sas.inner.CountCertificatesByNames(ctx, request.Names, time.Unix(0, request.Range.Earliest), time.Unix(0, request.Range.Latest))
	if err != nil {
		return nil, err
	}

	return &sapb.CountByNames{CountByNames: byNames}, nil
}

func (sas StorageAuthorityServerWrapper) CountRegistrationsByIP(ctx context.Context, request *sapb.CountRegistrationsByIPRequest) (*sapb.Count, error) {
	if core.IsAnyNilOrZero(request, request.Range, request.Range.Earliest, request.Range.Latest, request.Ip) {
		return nil, errIncompleteRequest
	}

	count, err := sas.inner.CountRegistrationsByIP(
		ctx,
		net.IP(request.Ip),
		time.Unix(0, request.Range.Earliest),
		time.Unix(0, request.Range.Latest))
	if err != nil {
		return nil, err
	}

	return &sapb.Count{Count: int64(count)}, nil
}

func (sas StorageAuthorityServerWrapper) CountRegistrationsByIPRange(ctx context.Context, request *sapb.CountRegistrationsByIPRequest) (*sapb.Count, error) {
	if core.IsAnyNilOrZero(request, request.Range, request.Range.Earliest, request.Range.Latest, request.Ip) {
		return nil, errIncompleteRequest
	}

	count, err := sas.inner.CountRegistrationsByIPRange(
		ctx,
		net.IP(request.Ip),
		time.Unix(0, request.Range.Earliest),
		time.Unix(0, request.Range.Latest))
	if err != nil {
		return nil, err
	}

	return &sapb.Count{Count: int64(count)}, nil
}

func (sas StorageAuthorityServerWrapper) CountOrders(ctx context.Context, request *sapb.CountOrdersRequest) (*sapb.Count, error) {
	if core.IsAnyNilOrZero(request, request.AccountID, request.Range, request.Range.Earliest, request.Range.Latest) {
		return nil, errIncompleteRequest
	}

	count, err := sas.inner.CountOrders(ctx,
		request.AccountID,
		time.Unix(0, request.Range.Earliest),
		time.Unix(0, request.Range.Latest),
	)
	if err != nil {
		return nil, err
	}

	return &sapb.Count{Count: int64(count)}, nil
}

func (sas StorageAuthorityServerWrapper) CountFQDNSets(ctx context.Context, request *sapb.CountFQDNSetsRequest) (*sapb.Count, error) {
	if core.IsAnyNilOrZero(request, request.Window, request.Domains) {
		return nil, errIncompleteRequest
	}

	window := time.Duration(request.Window)

	count, err := sas.inner.CountFQDNSets(ctx, window, request.Domains)
	if err != nil {
		return nil, err
	}

	return &sapb.Count{Count: int64(count)}, nil
}

func (sas StorageAuthorityServerWrapper) FQDNSetExists(ctx context.Context, request *sapb.FQDNSetExistsRequest) (*sapb.Exists, error) {
	return sas.inner.FQDNSetExists(ctx, request)
}

func (sac StorageAuthorityServerWrapper) PreviousCertificateExists(ctx context.Context, req *sapb.PreviousCertificateExistsRequest) (*sapb.Exists, error) {
	return sac.inner.PreviousCertificateExists(ctx, req)
}

func (sas StorageAuthorityServerWrapper) NewRegistration(ctx context.Context, request *corepb.Registration) (*corepb.Registration, error) {
	return sas.inner.NewRegistration(ctx, request)
}

func (sas StorageAuthorityServerWrapper) UpdateRegistration(ctx context.Context, request *corepb.Registration) (*emptypb.Empty, error) {
	return sas.inner.UpdateRegistration(ctx, request)
}

func (sas StorageAuthorityServerWrapper) AddCertificate(ctx context.Context, request *sapb.AddCertificateRequest) (*sapb.AddCertificateResponse, error) {
	return sas.inner.AddCertificate(ctx, request)
}

func (sas StorageAuthorityServerWrapper) DeactivateRegistration(ctx context.Context, request *sapb.RegistrationID) (*emptypb.Empty, error) {
	return sas.inner.DeactivateRegistration(ctx, request)
}

func (sas StorageAuthorityServerWrapper) NewOrder(ctx context.Context, request *corepb.Order) (*corepb.Order, error) {
	if request == nil || !newOrderValid(request) {
		return nil, errIncompleteRequest
	}

	return sas.inner.NewOrder(ctx, request)
}

func (sas StorageAuthorityServerWrapper) SetOrderProcessing(ctx context.Context, order *corepb.Order) (*emptypb.Empty, error) {
	if order == nil || !orderValid(order) {
		return nil, errIncompleteRequest
	}

	if err := sas.inner.SetOrderProcessing(ctx, order); err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) SetOrderError(ctx context.Context, order *corepb.Order) (*emptypb.Empty, error) {
	if order == nil || !orderValid(order) {
		return nil, errIncompleteRequest
	}

	if err := sas.inner.SetOrderError(ctx, order); err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) FinalizeOrder(ctx context.Context, order *corepb.Order) (*emptypb.Empty, error) {
	if order == nil || !orderValid(order) || order.CertificateSerial == "" {
		return nil, errIncompleteRequest
	}

	if err := sas.inner.FinalizeOrder(ctx, order); err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) GetOrder(ctx context.Context, request *sapb.OrderRequest) (*corepb.Order, error) {
	return sas.inner.GetOrder(ctx, request)
}

func (sas StorageAuthorityServerWrapper) GetOrderForNames(ctx context.Context, request *sapb.GetOrderForNamesRequest) (*corepb.Order, error) {
	return sas.inner.GetOrderForNames(ctx, request)
}

func (sas StorageAuthorityServerWrapper) GetAuthorization2(ctx context.Context, request *sapb.AuthorizationID2) (*corepb.Authorization, error) {
	return sas.inner.GetAuthorization2(ctx, request)
}

func (sas StorageAuthorityServerWrapper) RevokeCertificate(ctx context.Context, req *sapb.RevokeCertificateRequest) (*emptypb.Empty, error) {
	return sas.inner.RevokeCertificate(ctx, req)
}

func (sas StorageAuthorityServerWrapper) NewAuthorizations2(ctx context.Context, req *sapb.AddPendingAuthorizationsRequest) (*sapb.Authorization2IDs, error) {
	return sas.inner.NewAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) GetAuthorizations2(ctx context.Context, req *sapb.GetAuthorizationsRequest) (*sapb.Authorizations, error) {
	return sas.inner.GetAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) FinalizeAuthorization2(ctx context.Context, req *sapb.FinalizeAuthorizationRequest) (*emptypb.Empty, error) {
	return sas.inner.FinalizeAuthorization2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) GetPendingAuthorization2(ctx context.Context, req *sapb.GetPendingAuthorizationRequest) (*corepb.Authorization, error) {
	return sas.inner.GetPendingAuthorization2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) CountPendingAuthorizations2(ctx context.Context, req *sapb.RegistrationID) (*sapb.Count, error) {
	if core.IsAnyNilOrZero(req, req.Id) {
		return nil, errIncompleteRequest
	}

	return sas.inner.CountPendingAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) GetValidOrderAuthorizations2(ctx context.Context, req *sapb.GetValidOrderAuthorizationsRequest) (*sapb.Authorizations, error) {
	return sas.inner.GetValidOrderAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) CountInvalidAuthorizations2(ctx context.Context, req *sapb.CountInvalidAuthorizationsRequest) (*sapb.Count, error) {
	if core.IsAnyNilOrZero(req, req.RegistrationID, req.Hostname, req.Range, req.Range.Earliest, req.Range.Latest) {
		return nil, errIncompleteRequest
	}

	return sas.inner.CountInvalidAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) GetValidAuthorizations2(ctx context.Context, req *sapb.GetValidAuthorizationsRequest) (*sapb.Authorizations, error) {
	return sas.inner.GetValidAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) DeactivateAuthorization2(ctx context.Context, req *sapb.AuthorizationID2) (*emptypb.Empty, error) {
	return sas.inner.DeactivateAuthorization2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) AddBlockedKey(ctx context.Context, req *sapb.AddBlockedKeyRequest) (*emptypb.Empty, error) {
	// All request checking is done in the method
	return sas.inner.AddBlockedKey(ctx, req)
}

func (sas StorageAuthorityServerWrapper) KeyBlocked(ctx context.Context, req *sapb.KeyBlockedRequest) (*sapb.Exists, error) {
	// All request checking is done in the method
	return sas.inner.KeyBlocked(ctx, req)
}
