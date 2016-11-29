// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wrappers wraps the GRPC calls in the core interfaces.
package grpc

import (
	"crypto/x509"
	"errors"
	"time"

	"golang.org/x/net/context"
	ggrpc "google.golang.org/grpc"

	caPB "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/publisher"
	pubPB "github.com/letsencrypt/boulder/publisher/proto"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/revocation"
	vaPB "github.com/letsencrypt/boulder/va/proto"
)

type ValidationAuthorityGRPCServer struct {
	impl core.ValidationAuthority
}

var errIncompleteRequest = errors.New("Incomplete gRPC request message")
var errIncompleteResponse = errors.New("Incomplete gRPC response message")

func (s *ValidationAuthorityGRPCServer) PerformValidation(ctx context.Context, in *vaPB.PerformValidationRequest) (*vaPB.ValidationResult, error) {
	domain, challenge, authz, err := performValidationReqToArgs(in)
	if err != nil {
		return nil, err
	}
	records, err := s.impl.PerformValidation(ctx, domain, challenge, authz)
	// If the type of error was a ProblemDetails, we need to return
	// both that and the records to the caller (so it can update
	// the challenge / authz in the SA with the failing records).
	// The least error-prone way of doing this is to send a struct
	// as the RPC response and return a nil error on the RPC layer,
	// then unpack that into (records, error) to the caller.
	prob, ok := err.(*probs.ProblemDetails)
	if !ok && err != nil {
		return nil, err
	}
	return validationResultToPB(records, prob)
}

func (s *ValidationAuthorityGRPCServer) IsSafeDomain(ctx context.Context, in *vaPB.IsSafeDomainRequest) (*vaPB.IsDomainSafe, error) {
	return s.impl.IsSafeDomain(ctx, in)
}

func RegisterValidationAuthorityGRPCServer(s *ggrpc.Server, impl core.ValidationAuthority) error {
	rpcSrv := &ValidationAuthorityGRPCServer{impl}
	vaPB.RegisterVAServer(s, rpcSrv)
	return nil
}

type ValidationAuthorityGRPCClient struct {
	gc vaPB.VAClient
}

func NewValidationAuthorityGRPCClient(cc *ggrpc.ClientConn) core.ValidationAuthority {
	return &ValidationAuthorityGRPCClient{vaPB.NewVAClient(cc)}
}

// PerformValidation has the VA revalidate the specified challenge and returns
// the updated Challenge object.
func (vac ValidationAuthorityGRPCClient) PerformValidation(ctx context.Context, domain string, challenge core.Challenge, authz core.Authorization) ([]core.ValidationRecord, error) {
	req, err := argsToPerformValidationRequest(domain, challenge, authz)
	if err != nil {
		return nil, err
	}
	gRecords, err := vac.gc.PerformValidation(ctx, req)
	if err != nil {
		return nil, err
	}
	records, prob, err := pbToValidationResult(gRecords)
	if err != nil {
		return nil, err
	}

	return records, prob
}

// IsSafeDomain returns true if the domain given is determined to be safe by an
// third-party safe browsing API.
func (vac ValidationAuthorityGRPCClient) IsSafeDomain(ctx context.Context, req *vaPB.IsSafeDomainRequest) (*vaPB.IsDomainSafe, error) {
	return vac.gc.IsSafeDomain(ctx, req)
}

// PublisherClientWrapper is a wrapper needed to satisfy the interfaces
// in core/interfaces.go
type PublisherClientWrapper struct {
	inner   pubPB.PublisherClient
	timeout time.Duration
}

// NewPublisherClientWrapper returns an initialized PublisherClientWrapper
func NewPublisherClientWrapper(inner pubPB.PublisherClient, timeout time.Duration) *PublisherClientWrapper {
	return &PublisherClientWrapper{inner, timeout}
}

// SubmitToCT makes a call to the gRPC version of the publisher
func (pc *PublisherClientWrapper) SubmitToCT(ctx context.Context, der []byte) error {
	localCtx, cancel := context.WithTimeout(ctx, pc.timeout)
	defer cancel()
	_, err := pc.inner.SubmitToCT(localCtx, &pubPB.Request{Der: der})
	return err
}

// PublisherServerWrapper is a wrapper required to bridge the differences between the
// gRPC and previous AMQP interfaces
type PublisherServerWrapper struct {
	inner *publisher.Impl
}

// NewPublisherServerWrapper returns an initialized PublisherServerWrapper
func NewPublisherServerWrapper(inner *publisher.Impl) *PublisherServerWrapper {
	return &PublisherServerWrapper{inner}
}

// SubmitToCT calls the same method on the wrapped publisher.Impl since their interfaces
// are different
func (pub *PublisherServerWrapper) SubmitToCT(ctx context.Context, request *pubPB.Request) (*pubPB.Empty, error) {
	if request == nil || request.Der == nil {
		return nil, errors.New("incomplete SubmitToCT gRPC message")
	}
	return &pubPB.Empty{}, pub.inner.SubmitToCT(ctx, request.Der)
}

// CertificateAuthorityClientWrapper is the gRPC version of a core.CertificateAuthority client
type CertificateAuthorityClientWrapper struct {
	inner   caPB.CertificateAuthorityClient
	timeout time.Duration
}

func NewCertificateAuthorityClient(inner caPB.CertificateAuthorityClient, timeout time.Duration) *CertificateAuthorityClientWrapper {
	return &CertificateAuthorityClientWrapper{inner, timeout}
}

func (cac CertificateAuthorityClientWrapper) IssueCertificate(ctx context.Context, csr x509.CertificateRequest, regID int64) (core.Certificate, error) {
	localCtx, cancel := context.WithTimeout(ctx, cac.timeout)
	defer cancel()
	res, err := cac.inner.IssueCertificate(localCtx, &caPB.IssueCertificateRequest{
		Csr:            csr.Raw,
		RegistrationID: &regID,
	})
	if err != nil {
		return core.Certificate{}, err
	}
	return core.Certificate{
		RegistrationID: *res.RegistrationID,
		Serial:         *res.Serial,
		Digest:         *res.Digest,
		DER:            res.Der,
		Issued:         time.Unix(0, *res.Issued),
		Expires:        time.Unix(0, *res.Expires),
	}, nil
}

func (cac CertificateAuthorityClientWrapper) GenerateOCSP(ctx context.Context, ocspReq core.OCSPSigningRequest) ([]byte, error) {
	localCtx, cancel := context.WithTimeout(ctx, cac.timeout)
	defer cancel()
	reason := int32(ocspReq.Reason)
	revokedAt := ocspReq.RevokedAt.UnixNano()
	res, err := cac.inner.GenerateOCSP(localCtx, &caPB.GenerateOCSPRequest{
		CertDER:   ocspReq.CertDER,
		Status:    &ocspReq.Status,
		Reason:    &reason,
		RevokedAt: &revokedAt,
	})
	if err != nil {
		return nil, err
	}
	return res.Response, nil
}

// CertificateAuthorityServerWrapper is the gRPC version of a core.CertificateAuthority server
type CertificateAuthorityServerWrapper struct {
	inner core.CertificateAuthority
}

func NewCertificateAuthorityServer(inner core.CertificateAuthority) *CertificateAuthorityServerWrapper {
	return &CertificateAuthorityServerWrapper{inner}
}

func (cas *CertificateAuthorityServerWrapper) IssueCertificate(ctx context.Context, request *caPB.IssueCertificateRequest) (*corepb.Certificate, error) {
	csr, err := x509.ParseCertificateRequest(request.Csr)
	if err != nil {
		return nil, err
	}
	res, err := cas.inner.IssueCertificate(ctx, *csr, *request.RegistrationID)
	if err != nil {
		return nil, err
	}
	issued, expires := res.Issued.UnixNano(), res.Expires.UnixNano()
	return &corepb.Certificate{
		RegistrationID: &res.RegistrationID,
		Serial:         &res.Serial,
		Digest:         &res.Digest,
		Der:            res.DER,
		Issued:         &issued,
		Expires:        &expires,
	}, nil
}

func (cas *CertificateAuthorityServerWrapper) GenerateOCSP(ctx context.Context, request *caPB.GenerateOCSPRequest) (*caPB.OCSPResponse, error) {
	res, err := cas.inner.GenerateOCSP(ctx, core.OCSPSigningRequest{
		CertDER:   request.CertDER,
		Status:    *request.Status,
		Reason:    revocation.Reason(*request.Reason),
		RevokedAt: time.Unix(0, *request.RevokedAt),
	})
	if err != nil {
		return nil, err
	}
	return &caPB.OCSPResponse{Response: res}, nil
}

// RegistrationAuthorityClientWrapper is the gRPC version of a core.RegistrationAuthority client
type RegistrationAuthorityClientWrapper struct {
	inner   rapb.RegistrationAuthorityClient
	timeout time.Duration
}

func NewRegistrationAuthorityClient(inner rapb.RegistrationAuthorityClient, timeout time.Duration) *RegistrationAuthorityClientWrapper {
	return &RegistrationAuthorityClientWrapper{inner, timeout}
}

func (rac RegistrationAuthorityClientWrapper) NewRegistration(ctx context.Context, reg core.Registration) (core.Registration, error) {
	localCtx, cancel := context.WithTimeout(ctx, rac.timeout)
	defer cancel()

	req, err := registrationToPB(reg)
	if err != nil {
		return core.Registration{}, err
	}

	response, err := rac.inner.NewRegistration(localCtx, req)
	if err != nil {
		return core.Registration{}, unwrapError(err)
	}

	if response == nil || !registrationValid(response) {
		return core.Registration{}, errIncompleteResponse
	}

	r, err := pbToRegistration(response)
	return r, err
}

func (rac RegistrationAuthorityClientWrapper) NewAuthorization(ctx context.Context, authz core.Authorization, regID int64) (core.Authorization, error) {
	localCtx, cancel := context.WithTimeout(ctx, rac.timeout)
	defer cancel()

	req, err := authzToPB(authz)
	if err != nil {
		return core.Authorization{}, err
	}

	response, err := rac.inner.NewAuthorization(localCtx, &rapb.NewAuthorizationRequest{Authz: req, RegID: &regID})
	if err != nil {
		return core.Authorization{}, unwrapError(err)
	}

	if response == nil || !authorizationValid(response) {
		return core.Authorization{}, errIncompleteResponse
	}

	return pbToAuthz(response)
}

func (rac RegistrationAuthorityClientWrapper) NewCertificate(ctx context.Context, csr core.CertificateRequest, regID int64) (core.Certificate, error) {
	localCtx, cancel := context.WithTimeout(ctx, rac.timeout)
	defer cancel()

	response, err := rac.inner.NewCertificate(localCtx, &rapb.NewCertificateRequest{Csr: csr.Bytes, RegID: &regID})
	if err != nil {
		return core.Certificate{}, unwrapError(err)
	}

	if response == nil || response.RegistrationID == nil || response.Serial == nil || response.Digest == nil || response.Der == nil || response.Issued == nil || response.Expires == nil {
		return core.Certificate{}, errIncompleteResponse
	}

	return core.Certificate{
		RegistrationID: *response.RegistrationID,
		Serial:         *response.Serial,
		Digest:         *response.Digest,
		DER:            response.Der,
		Issued:         time.Unix(0, *response.Issued),
		Expires:        time.Unix(0, *response.Expires),
	}, nil
}

func (rac RegistrationAuthorityClientWrapper) UpdateRegistration(ctx context.Context, base, updates core.Registration) (core.Registration, error) {
	localCtx, cancel := context.WithTimeout(ctx, rac.timeout)
	defer cancel()

	basePB, err := registrationToPB(base)
	if err != nil {
		return core.Registration{}, err
	}
	updatePB, err := registrationToPB(updates)
	if err != nil {
		return core.Registration{}, err
	}

	response, err := rac.inner.UpdateRegistration(localCtx, &rapb.UpdateRegistrationRequest{Base: basePB, Update: updatePB})
	if err != nil {
		return core.Registration{}, unwrapError(err)
	}

	if response == nil || !registrationValid(response) {
		return core.Registration{}, errIncompleteResponse
	}

	return pbToRegistration(response)
}

func (rac RegistrationAuthorityClientWrapper) UpdateAuthorization(ctx context.Context, authz core.Authorization, challengeIndex int, chall core.Challenge) (core.Authorization, error) {
	localCtx, cancel := context.WithTimeout(ctx, rac.timeout)
	defer cancel()

	authzPB, err := authzToPB(authz)
	if err != nil {
		return core.Authorization{}, err
	}
	challPB, err := challengeToPB(chall)
	if err != nil {
		return core.Authorization{}, err
	}

	ind := int64(challengeIndex)

	response, err := rac.inner.UpdateAuthorization(localCtx, &rapb.UpdateAuthorizationRequest{
		Authz:          authzPB,
		ChallengeIndex: &ind,
		Response:       challPB,
	})
	if err != nil {
		return core.Authorization{}, unwrapError(err)
	}

	if response == nil || !authorizationValid(response) {
		return core.Authorization{}, errIncompleteResponse
	}

	return pbToAuthz(response)
}

func (rac RegistrationAuthorityClientWrapper) RevokeCertificateWithReg(ctx context.Context, cert x509.Certificate, code revocation.Reason, regID int64) error {
	localCtx, cancel := context.WithTimeout(ctx, rac.timeout)
	defer cancel()

	reason := int64(code)
	_, err := rac.inner.RevokeCertificateWithReg(localCtx, &rapb.RevokeCertificateWithRegRequest{
		Cert:  cert.Raw,
		Code:  &reason,
		RegID: &regID,
	})
	if err != nil {
		return unwrapError(err)
	}

	return nil
}

func (rac RegistrationAuthorityClientWrapper) DeactivateRegistration(ctx context.Context, reg core.Registration) error {
	localCtx, cancel := context.WithTimeout(ctx, rac.timeout)
	defer cancel()

	regPB, err := registrationToPB(reg)
	if err != nil {
		return err
	}

	_, err = rac.inner.DeactivateRegistration(localCtx, regPB)
	if err != nil {
		return unwrapError(err)
	}

	return nil
}

func (rac RegistrationAuthorityClientWrapper) DeactivateAuthorization(ctx context.Context, auth core.Authorization) error {
	localCtx, cancel := context.WithTimeout(ctx, rac.timeout)
	defer cancel()

	authzPB, err := authzToPB(auth)
	if err != nil {
		return err
	}

	_, err = rac.inner.DeactivateAuthorization(localCtx, authzPB)
	if err != nil {
		return unwrapError(err)
	}

	return nil
}

func (rac RegistrationAuthorityClientWrapper) AdministrativelyRevokeCertificate(ctx context.Context, cert x509.Certificate, code revocation.Reason, adminName string) error {
	localCtx, cancel := context.WithTimeout(ctx, rac.timeout)
	defer cancel()

	reason := int64(code)
	_, err := rac.inner.AdministrativelyRevokeCertificate(localCtx, &rapb.AdministrativelyRevokeCertificateRequest{
		Cert:      cert.Raw,
		Code:      &reason,
		AdminName: &adminName,
	})
	if err != nil {
		return unwrapError(err)
	}

	return nil
}

// RegistrationAuthorityServerWrapper is the gRPC version of a core.RegistrationAuthority server
type RegistrationAuthorityServerWrapper struct {
	inner core.RegistrationAuthority
}

func NewRegistrationAuthorityServer(inner core.RegistrationAuthority) *RegistrationAuthorityServerWrapper {
	return &RegistrationAuthorityServerWrapper{inner}
}

func (ras *RegistrationAuthorityServerWrapper) NewRegistration(ctx context.Context, request *rapb.Registration) (*rapb.Registration, error) {
	if request == nil || !registrationValid(request) {
		return nil, errIncompleteRequest
	}
	reg, err := pbToRegistration(request)
	if err != nil {
		return nil, err
	}
	newReg, err := ras.inner.NewRegistration(ctx, reg)
	if err != nil {
		return nil, wrapError(err)
	}
	return registrationToPB(newReg)
}

func (ras *RegistrationAuthorityServerWrapper) NewAuthorization(ctx context.Context, request *rapb.NewAuthorizationRequest) (*rapb.Authorization, error) {
	if request == nil || !authorizationValid(request.Authz) || request.RegID == nil {
		return nil, errIncompleteRequest
	}
	authz, err := pbToAuthz(request.Authz)
	if err != nil {
		return nil, err
	}
	newAuthz, err := ras.inner.NewAuthorization(ctx, authz, *request.RegID)
	if err != nil {
		return nil, wrapError(err)
	}
	return authzToPB(newAuthz)
}

func (ras *RegistrationAuthorityServerWrapper) NewCertificate(ctx context.Context, request *rapb.NewCertificateRequest) (*corepb.Certificate, error) {
	if request == nil || request.Csr == nil || request.RegID == nil {
		return nil, errIncompleteRequest
	}
	csr, err := x509.ParseCertificateRequest(request.Csr)
	if err != nil {
		return nil, err
	}
	cert, err := ras.inner.NewCertificate(ctx, core.CertificateRequest{CSR: csr, Bytes: request.Csr}, *request.RegID)
	if err != nil {
		return nil, wrapError(err)
	}
	issued := cert.Issued.UnixNano()
	expires := cert.Expires.UnixNano()
	return &corepb.Certificate{
		RegistrationID: &cert.RegistrationID,
		Serial:         &cert.Serial,
		Digest:         &cert.Digest,
		Der:            cert.DER,
		Issued:         &issued,
		Expires:        &expires,
	}, nil
}

func (ras *RegistrationAuthorityServerWrapper) UpdateRegistration(ctx context.Context, request *rapb.UpdateRegistrationRequest) (*rapb.Registration, error) {
	if request == nil || !registrationValid(request.Base) || !registrationValid(request.Update) {
		return nil, errIncompleteRequest
	}
	base, err := pbToRegistration(request.Base)
	if err != nil {
		return nil, err
	}
	update, err := pbToRegistration(request.Update)
	if err != nil {
		return nil, err
	}
	newReg, err := ras.inner.UpdateRegistration(ctx, base, update)
	if err != nil {
		return nil, wrapError(err)
	}
	return registrationToPB(newReg)
}

func (ras *RegistrationAuthorityServerWrapper) UpdateAuthorization(ctx context.Context, request *rapb.UpdateAuthorizationRequest) (*rapb.Authorization, error) {
	if request == nil || !authorizationValid(request.Authz) || request.ChallengeIndex == nil || request.Response == nil {
		return nil, errIncompleteRequest
	}
	authz, err := pbToAuthz(request.Authz)
	if err != nil {
		return nil, err
	}
	chall, err := pbToChallenge(request.Response)
	if err != nil {
		return nil, err
	}
	newAuthz, err := ras.inner.UpdateAuthorization(ctx, authz, int(*request.ChallengeIndex), chall)
	if err != nil {
		return nil, wrapError(err)
	}
	return authzToPB(newAuthz)
}

func (ras *RegistrationAuthorityServerWrapper) RevokeCertificateWithReg(ctx context.Context, request *rapb.RevokeCertificateWithRegRequest) (*corepb.Empty, error) {
	if request == nil || request.Cert == nil || request.Code == nil || request.RegID == nil {
		return nil, errIncompleteRequest
	}
	cert, err := x509.ParseCertificate(request.Cert)
	if err != nil {
		return nil, err
	}
	err = ras.inner.RevokeCertificateWithReg(ctx, *cert, revocation.Reason(*request.Code), *request.RegID)
	if err != nil {
		return nil, wrapError(err)
	}
	return &corepb.Empty{}, nil
}

func (ras *RegistrationAuthorityServerWrapper) DeactivateRegistration(ctx context.Context, request *rapb.Registration) (*corepb.Empty, error) {
	if request == nil || !registrationValid(request) {
		return nil, errIncompleteRequest
	}
	reg, err := pbToRegistration(request)
	if err != nil {
		return nil, err
	}
	err = ras.inner.DeactivateRegistration(ctx, reg)
	if err != nil {
		return nil, wrapError(err)
	}
	return &corepb.Empty{}, nil
}

func (ras *RegistrationAuthorityServerWrapper) DeactivateAuthorization(ctx context.Context, request *rapb.Authorization) (*corepb.Empty, error) {
	if request == nil || !authorizationValid(request) {
		return nil, errIncompleteRequest
	}
	authz, err := pbToAuthz(request)
	if err != nil {
		return nil, err
	}
	err = ras.inner.DeactivateAuthorization(ctx, authz)
	if err != nil {
		return nil, wrapError(err)
	}
	return &corepb.Empty{}, nil
}

func (ras *RegistrationAuthorityServerWrapper) AdministrativelyRevokeCertificate(ctx context.Context, request *rapb.AdministrativelyRevokeCertificateRequest) (*corepb.Empty, error) {
	if request == nil || request.Cert == nil || request.Code == nil || request.AdminName == nil {
		return nil, errIncompleteRequest
	}
	cert, err := x509.ParseCertificate(request.Cert)
	if err != nil {
		return nil, err
	}
	err = ras.inner.AdministrativelyRevokeCertificate(ctx, *cert, revocation.Reason(*request.Code), *request.AdminName)
	if err != nil {
		return nil, wrapError(err)
	}
	return &corepb.Empty{}, nil
}
