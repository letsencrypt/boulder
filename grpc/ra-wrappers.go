// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wrappers wraps the GRPC calls in the core interfaces.
package grpc

import (
	"context"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// RegistrationAuthorityClientWrapper is the gRPC version of a core.RegistrationAuthority client
type RegistrationAuthorityClientWrapper struct {
	inner rapb.RegistrationAuthorityClient
}

func NewRegistrationAuthorityClient(inner rapb.RegistrationAuthorityClient) *RegistrationAuthorityClientWrapper {
	return &RegistrationAuthorityClientWrapper{inner}
}

func (rac RegistrationAuthorityClientWrapper) NewRegistration(ctx context.Context, request *corepb.Registration) (*corepb.Registration, error) {
	return rac.inner.NewRegistration(ctx, request)
}

func (rac RegistrationAuthorityClientWrapper) NewAuthorization(ctx context.Context, request *rapb.NewAuthorizationRequest) (*corepb.Authorization, error) {
	return rac.inner.NewAuthorization(ctx, request)
}

func (rac RegistrationAuthorityClientWrapper) NewCertificate(ctx context.Context, req *rapb.NewCertificateRequest) (*corepb.Certificate, error) {
	return rac.inner.NewCertificate(ctx, req)
}

func (rac RegistrationAuthorityClientWrapper) UpdateRegistration(ctx context.Context, req *rapb.UpdateRegistrationRequest) (*corepb.Registration, error) {
	return rac.inner.UpdateRegistration(ctx, req)
}

func (rac RegistrationAuthorityClientWrapper) PerformValidation(ctx context.Context, req *rapb.PerformValidationRequest) (*corepb.Authorization, error) {
	return rac.inner.PerformValidation(ctx, req)
}

func (rac RegistrationAuthorityClientWrapper) RevokeCertificateWithReg(ctx context.Context, req *rapb.RevokeCertificateWithRegRequest) (*emptypb.Empty, error) {
	return rac.inner.RevokeCertificateWithReg(ctx, req)
}

func (rac RegistrationAuthorityClientWrapper) DeactivateRegistration(ctx context.Context, reg *corepb.Registration) (*emptypb.Empty, error) {
	return rac.inner.DeactivateRegistration(ctx, reg)
}

func (rac RegistrationAuthorityClientWrapper) DeactivateAuthorization(ctx context.Context, auth core.Authorization) error {
	authzPB, err := AuthzToPB(auth)
	if err != nil {
		return err
	}

	_, err = rac.inner.DeactivateAuthorization(ctx, authzPB)
	if err != nil {
		return err
	}

	return nil
}

func (rac RegistrationAuthorityClientWrapper) AdministrativelyRevokeCertificate(ctx context.Context, request *rapb.AdministrativelyRevokeCertificateRequest) (*emptypb.Empty, error) {
	return rac.inner.AdministrativelyRevokeCertificate(ctx, request)
}

func (ras *RegistrationAuthorityClientWrapper) NewOrder(ctx context.Context, request *rapb.NewOrderRequest) (*corepb.Order, error) {
	return ras.inner.NewOrder(ctx, request)
}

func (ras *RegistrationAuthorityClientWrapper) FinalizeOrder(ctx context.Context, request *rapb.FinalizeOrderRequest) (*corepb.Order, error) {
	resp, err := ras.inner.FinalizeOrder(ctx, request)
	if err != nil {
		return nil, err
	}
	if resp == nil || !orderValid(resp) {
		return nil, errIncompleteResponse
	}
	return resp, nil
}

// RegistrationAuthorityServerWrapper is the gRPC version of a core.RegistrationAuthority server
type RegistrationAuthorityServerWrapper struct {
	rapb.UnimplementedRegistrationAuthorityServer
	inner core.RegistrationAuthority
}

func NewRegistrationAuthorityServer(inner core.RegistrationAuthority) *RegistrationAuthorityServerWrapper {
	return &RegistrationAuthorityServerWrapper{inner: inner}
}

func (ras *RegistrationAuthorityServerWrapper) NewRegistration(ctx context.Context, request *corepb.Registration) (*corepb.Registration, error) {
	return ras.inner.NewRegistration(ctx, request)
}

func (ras *RegistrationAuthorityServerWrapper) NewAuthorization(ctx context.Context, request *rapb.NewAuthorizationRequest) (*corepb.Authorization, error) {
	return ras.inner.NewAuthorization(ctx, request)
}

func (ras *RegistrationAuthorityServerWrapper) NewCertificate(ctx context.Context, request *rapb.NewCertificateRequest) (*corepb.Certificate, error) {
	return ras.inner.NewCertificate(ctx, request)
}

func (ras *RegistrationAuthorityServerWrapper) UpdateRegistration(ctx context.Context, req *rapb.UpdateRegistrationRequest) (*corepb.Registration, error) {
	return ras.inner.UpdateRegistration(ctx, req)
}

func (ras *RegistrationAuthorityServerWrapper) PerformValidation(ctx context.Context, request *rapb.PerformValidationRequest) (*corepb.Authorization, error) {
	return ras.inner.PerformValidation(ctx, request)
}

func (ras *RegistrationAuthorityServerWrapper) RevokeCertificateWithReg(ctx context.Context, request *rapb.RevokeCertificateWithRegRequest) (*emptypb.Empty, error) {
	return ras.inner.RevokeCertificateWithReg(ctx, request)
}

func (ras *RegistrationAuthorityServerWrapper) DeactivateRegistration(ctx context.Context, request *corepb.Registration) (*emptypb.Empty, error) {
	return ras.inner.DeactivateRegistration(ctx, request)
}

func (ras *RegistrationAuthorityServerWrapper) DeactivateAuthorization(ctx context.Context, request *corepb.Authorization) (*emptypb.Empty, error) {
	if request == nil || !authorizationValid(request) {
		return nil, errIncompleteRequest
	}
	authz, err := PBToAuthz(request)
	if err != nil {
		return nil, err
	}
	err = ras.inner.DeactivateAuthorization(ctx, authz)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (ras *RegistrationAuthorityServerWrapper) AdministrativelyRevokeCertificate(ctx context.Context, request *rapb.AdministrativelyRevokeCertificateRequest) (*emptypb.Empty, error) {
	return ras.inner.AdministrativelyRevokeCertificate(ctx, request)
}

func (ras *RegistrationAuthorityServerWrapper) NewOrder(ctx context.Context, request *rapb.NewOrderRequest) (*corepb.Order, error) {
	return ras.inner.NewOrder(ctx, request)
}

func (ras *RegistrationAuthorityServerWrapper) FinalizeOrder(ctx context.Context, request *rapb.FinalizeOrderRequest) (*corepb.Order, error) {
	if request == nil || request.Order == nil || request.Csr == nil {
		return nil, errIncompleteRequest
	}

	return ras.inner.FinalizeOrder(ctx, request)
}
