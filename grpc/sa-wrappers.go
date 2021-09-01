// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wrappers wraps the GRPC calls in the core interfaces.
package grpc

import (
	"context"

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

func (sac StorageAuthorityClientWrapper) GetCertificateStatus(ctx context.Context, req *sapb.Serial) (*corepb.CertificateStatus, error) {
	return sac.inner.GetCertificateStatus(ctx, req)
}

func (sac StorageAuthorityClientWrapper) CountCertificatesByNames(ctx context.Context, req *sapb.CountCertificatesByNamesRequest) (*sapb.CountByNames, error) {
	return sac.inner.CountCertificatesByNames(ctx, req)
}

func (sac StorageAuthorityClientWrapper) CountRegistrationsByIP(ctx context.Context, req *sapb.CountRegistrationsByIPRequest) (*sapb.Count, error) {
	return sac.inner.CountRegistrationsByIP(ctx, req)
}

func (sac StorageAuthorityClientWrapper) CountRegistrationsByIPRange(ctx context.Context, req *sapb.CountRegistrationsByIPRequest) (*sapb.Count, error) {
	return sac.inner.CountRegistrationsByIPRange(ctx, req)
}

func (sac StorageAuthorityClientWrapper) CountOrders(ctx context.Context, req *sapb.CountOrdersRequest) (*sapb.Count, error) {
	return sac.inner.CountOrders(ctx, req)
}

func (sac StorageAuthorityClientWrapper) CountFQDNSets(ctx context.Context, req *sapb.CountFQDNSetsRequest) (*sapb.Count, error) {
	return sac.inner.CountFQDNSets(ctx, req)
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

func (sas StorageAuthorityClientWrapper) NewOrder(ctx context.Context, request *sapb.NewOrderRequest) (*corepb.Order, error) {
	return sas.inner.NewOrder(ctx, request)
}

func (sac StorageAuthorityClientWrapper) SetOrderProcessing(ctx context.Context, req *sapb.OrderRequest) (*emptypb.Empty, error) {
	return sac.inner.SetOrderProcessing(ctx, req)
}

func (sac StorageAuthorityClientWrapper) SetOrderError(ctx context.Context, request *sapb.SetOrderErrorRequest) (*emptypb.Empty, error) {
	return sac.inner.SetOrderError(ctx, request)
}

func (sac StorageAuthorityClientWrapper) FinalizeOrder(ctx context.Context, req *sapb.FinalizeOrderRequest) (*emptypb.Empty, error) {
	return sac.inner.FinalizeOrder(ctx, req)
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
	return sas.inner.CountPendingAuthorizations2(ctx, req)
}

func (sas StorageAuthorityClientWrapper) GetValidOrderAuthorizations2(ctx context.Context, req *sapb.GetValidOrderAuthorizationsRequest) (*sapb.Authorizations, error) {
	return sas.inner.GetValidOrderAuthorizations2(ctx, req)
}

func (sas StorageAuthorityClientWrapper) CountInvalidAuthorizations2(ctx context.Context, req *sapb.CountInvalidAuthorizationsRequest) (*sapb.Count, error) {
	return sas.inner.CountInvalidAuthorizations2(ctx, req)
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
	return sas.inner.GetCertificateStatus(ctx, request)
}

func (sas StorageAuthorityServerWrapper) CountCertificatesByNames(ctx context.Context, req *sapb.CountCertificatesByNamesRequest) (*sapb.CountByNames, error) {
	return sas.inner.CountCertificatesByNames(ctx, req)
}

func (sas StorageAuthorityServerWrapper) CountRegistrationsByIP(ctx context.Context, request *sapb.CountRegistrationsByIPRequest) (*sapb.Count, error) {
	return sas.inner.CountRegistrationsByIP(ctx, request)
}

func (sas StorageAuthorityServerWrapper) CountRegistrationsByIPRange(ctx context.Context, request *sapb.CountRegistrationsByIPRequest) (*sapb.Count, error) {
	return sas.inner.CountRegistrationsByIPRange(ctx, request)
}

func (sas StorageAuthorityServerWrapper) CountOrders(ctx context.Context, request *sapb.CountOrdersRequest) (*sapb.Count, error) {
	return sas.inner.CountOrders(ctx, request)
}

func (sas StorageAuthorityServerWrapper) CountFQDNSets(ctx context.Context, request *sapb.CountFQDNSetsRequest) (*sapb.Count, error) {
	return sas.inner.CountFQDNSets(ctx, request)
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

func (sas StorageAuthorityServerWrapper) NewOrder(ctx context.Context, request *sapb.NewOrderRequest) (*corepb.Order, error) {
	return sas.inner.NewOrder(ctx, request)
}

func (sas StorageAuthorityServerWrapper) SetOrderProcessing(ctx context.Context, req *sapb.OrderRequest) (*emptypb.Empty, error) {
	return sas.inner.SetOrderProcessing(ctx, req)
}

func (sas StorageAuthorityServerWrapper) SetOrderError(ctx context.Context, request *sapb.SetOrderErrorRequest) (*emptypb.Empty, error) {
	return sas.inner.SetOrderError(ctx, request)
}

func (sas StorageAuthorityServerWrapper) FinalizeOrder(ctx context.Context, req *sapb.FinalizeOrderRequest) (*emptypb.Empty, error) {
	return sas.inner.FinalizeOrder(ctx, req)
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
	return sas.inner.CountPendingAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) GetValidOrderAuthorizations2(ctx context.Context, req *sapb.GetValidOrderAuthorizationsRequest) (*sapb.Authorizations, error) {
	return sas.inner.GetValidOrderAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) CountInvalidAuthorizations2(ctx context.Context, req *sapb.CountInvalidAuthorizationsRequest) (*sapb.Count, error) {
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
