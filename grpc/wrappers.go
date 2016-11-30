// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wrappers wraps the GRPC calls in the core interfaces.
package grpc

import (
	"crypto/x509"
	"errors"
	"net"
	"time"

	"golang.org/x/net/context"
	ggrpc "google.golang.org/grpc"
	"gopkg.in/square/go-jose.v1"

	caPB "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/publisher"
	pubPB "github.com/letsencrypt/boulder/publisher/proto"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/revocation"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	vaPB "github.com/letsencrypt/boulder/va/proto"
)

type ValidationAuthorityGRPCServer struct {
	impl core.ValidationAuthority
}

var (
	errIncompleteRequest  = errors.New("Incomplete gRPC request message")
	errIncompleteResponse = errors.New("Incomplete gRPC response message")
)

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

	response, err := rac.inner.NewCertificate(localCtx, &corepb.CertificateRequest{Csr: csr.Bytes, RegID: &regID})
	if err != nil {
		return core.Certificate{}, unwrapError(err)
	}

	if response == nil || !certificateValid(response) {
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

func (ras *RegistrationAuthorityServerWrapper) NewRegistration(ctx context.Context, request *corepb.Registration) (*corepb.Registration, error) {
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

func (ras *RegistrationAuthorityServerWrapper) NewAuthorization(ctx context.Context, request *rapb.NewAuthorizationRequest) (*corepb.Authorization, error) {
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

func (ras *RegistrationAuthorityServerWrapper) NewCertificate(ctx context.Context, request *corepb.CertificateRequest) (*corepb.Certificate, error) {
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

func (ras *RegistrationAuthorityServerWrapper) UpdateRegistration(ctx context.Context, request *rapb.UpdateRegistrationRequest) (*corepb.Registration, error) {
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

func (ras *RegistrationAuthorityServerWrapper) UpdateAuthorization(ctx context.Context, request *rapb.UpdateAuthorizationRequest) (*corepb.Authorization, error) {
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

func (ras *RegistrationAuthorityServerWrapper) DeactivateRegistration(ctx context.Context, request *corepb.Registration) (*corepb.Empty, error) {
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

func (ras *RegistrationAuthorityServerWrapper) DeactivateAuthorization(ctx context.Context, request *corepb.Authorization) (*corepb.Empty, error) {
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

// StorageAuthorityClientWrapper is the gRPC version of a core.StorageAuthority client
type StorageAuthorityClientWrapper struct {
	inner   sapb.StorageAuthorityClient
	timeout time.Duration
}

func NewStorageAuthorityClient(inner sapb.StorageAuthorityClient, timeout time.Duration) *StorageAuthorityClientWrapper {
	return &StorageAuthorityClientWrapper{inner, timeout}
}

func (sac StorageAuthorityClientWrapper) GetRegistration(ctx context.Context, regID int64) (core.Registration, error) {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	response, err := sac.inner.GetRegistration(localCtx, &sapb.RegistrationID{Id: &regID})
	if err != nil {
		return core.Registration{}, unwrapError(err)
	}

	if response == nil || !registrationValid(response) {
		return core.Registration{}, errIncompleteResponse
	}

	return pbToRegistration(response)
}

func (sac StorageAuthorityClientWrapper) GetRegistrationByKey(ctx context.Context, key jose.JsonWebKey) (core.Registration, error) {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	keyBytes, err := key.MarshalJSON()
	if err != nil {
		return core.Registration{}, err
	}

	response, err := sac.inner.GetRegistrationByKey(localCtx, &sapb.JsonWebKey{Jwk: keyBytes})
	if err != nil {
		return core.Registration{}, unwrapError(err)
	}

	if response == nil || !registrationValid(response) {
		return core.Registration{}, errIncompleteResponse
	}

	return pbToRegistration(response)
}

func (sac StorageAuthorityClientWrapper) GetAuthorization(ctx context.Context, authID string) (core.Authorization, error) {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	response, err := sac.inner.GetAuthorization(localCtx, &sapb.AuthorizationID{Id: &authID})
	if err != nil {
		return core.Authorization{}, unwrapError(err)
	}

	if response == nil || !authorizationValid(response) {
		return core.Authorization{}, errIncompleteResponse
	}

	return pbToAuthz(response)
}

func (sac StorageAuthorityClientWrapper) GetValidAuthorizations(ctx context.Context, regID int64, domains []string, now time.Time) (map[string]*core.Authorization, error) {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	nowUnix := now.UnixNano()

	response, err := sac.inner.GetValidAuthorizations(localCtx, &sapb.GetValidAuthorizationsRequest{
		RegistrationID: &regID,
		Domains:        domains,
		Now:            &nowUnix,
	})
	if err != nil {
		return nil, unwrapError(err)
	}

	if response == nil {
		return nil, errIncompleteResponse
	}

	auths := make(map[string]*core.Authorization, len(response.Valid))
	for _, element := range response.Valid {
		if element == nil || element.Domain == nil || !authorizationValid(element.Authz) {
			return nil, errIncompleteResponse
		}
		authz, err := pbToAuthz(element.Authz)
		if err != nil {
			return nil, err
		}
		auths[*element.Domain] = &authz
	}
	return auths, nil
}

func (sac StorageAuthorityClientWrapper) GetCertificate(ctx context.Context, serial string) (core.Certificate, error) {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	response, err := sac.inner.GetCertificate(localCtx, &sapb.Serial{Serial: &serial})
	if err != nil {
		return core.Certificate{}, unwrapError(err)
	}

	if response == nil || !certificateValid(response) {
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

func (sac StorageAuthorityClientWrapper) GetCertificateStatus(ctx context.Context, serial string) (core.CertificateStatus, error) {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	response, err := sac.inner.GetCertificateStatus(localCtx, &sapb.Serial{Serial: &serial})
	if err != nil {
		return core.CertificateStatus{}, unwrapError(err)
	}

	if response == nil || response.Serial == nil || response.SubscriberApproved == nil || response.Status == nil || response.OcspLastUpdated == nil || response.RevokedDate == nil || response.RevokedReason == nil || response.LastExpirationNagSent == nil || response.OcspResponse == nil || response.NotAfter == nil || response.IsExpired == nil {
		return core.CertificateStatus{}, errIncompleteResponse
	}

	return core.CertificateStatus{
		Serial:                *response.Serial,
		SubscriberApproved:    *response.SubscriberApproved,
		OCSPLastUpdated:       time.Unix(0, *response.OcspLastUpdated),
		RevokedDate:           time.Unix(0, *response.RevokedDate),
		RevokedReason:         revocation.Reason(*response.RevokedReason),
		LastExpirationNagSent: time.Unix(0, *response.LastExpirationNagSent),
		OCSPResponse:          response.OcspResponse,
		NotAfter:              time.Unix(0, *response.NotAfter),
		IsExpired:             *response.IsExpired,
	}, nil
}

func (sac StorageAuthorityClientWrapper) CountCertificatesRange(ctx context.Context, earliest, latest time.Time) (int64, error) {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	earliestNano := earliest.UnixNano()
	latestNano := latest.UnixNano()

	response, err := sac.inner.CountCertificatesRange(localCtx, &sapb.Range{
		Earliest: &earliestNano,
		Latest:   &latestNano,
	})
	if err != nil {
		return 0, unwrapError(err)
	}

	if response == nil || response.Count == nil {
		return 0, errIncompleteResponse
	}

	return *response.Count, nil
}

func (sac StorageAuthorityClientWrapper) CountCertificatesByNames(ctx context.Context, domains []string, earliest, latest time.Time) (map[string]int, error) {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	earliestNano := earliest.UnixNano()
	latestNano := latest.UnixNano()

	response, err := sac.inner.CountCertificatesByNames(localCtx, &sapb.CountCertificatesByNamesRequest{
		Names: domains,
		Range: &sapb.Range{
			Earliest: &earliestNano,
			Latest:   &latestNano,
		},
	})
	if err != nil {
		return nil, unwrapError(err)
	}

	if response == nil || response.CountByNames == nil {
		return nil, errIncompleteResponse
	}

	names := make(map[string]int, len(response.CountByNames))
	for _, element := range response.CountByNames {
		if element == nil || element.Name == nil || element.Count == nil {
			return nil, errIncompleteResponse
		}
		names[*element.Name] = int(*element.Count)
	}

	return names, nil
}

func (sac StorageAuthorityClientWrapper) CountRegistrationsByIP(ctx context.Context, ip net.IP, earliest, latest time.Time) (int, error) {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	earliestNano := earliest.UnixNano()
	latestNano := latest.UnixNano()
	ipStr := ip.String()

	response, err := sac.inner.CountRegistrationsByIP(localCtx, &sapb.CountRegistrationsByIPRequest{
		Range: &sapb.Range{
			Earliest: &earliestNano,
			Latest:   &latestNano,
		},
		Ip: &ipStr,
	})
	if err != nil {
		return 0, unwrapError(err)
	}

	if response == nil || response.Count == nil {
		return 0, errIncompleteResponse
	}

	return int(*response.Count), nil
}

func (sac StorageAuthorityClientWrapper) CountPendingAuthorizations(ctx context.Context, regID int64) (int, error) {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	response, err := sac.inner.CountPendingAuthorizations(localCtx, &sapb.RegistrationID{Id: &regID})
	if err != nil {
		return 0, unwrapError(err)
	}

	if response == nil || response.Count == nil {
		return 0, errIncompleteResponse
	}

	return int(*response.Count), nil
}

func (sac StorageAuthorityClientWrapper) GetSCTReceipt(ctx context.Context, serial, logID string) (core.SignedCertificateTimestamp, error) {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	response, err := sac.inner.GetSCTReceipt(localCtx, &sapb.GetSCTReceiptRequest{Serial: &serial, LogID: &logID})
	if err != nil {
		return core.SignedCertificateTimestamp{}, unwrapError(err)
	}

	if response == nil || !sctValid(response) {
		return core.SignedCertificateTimestamp{}, errIncompleteResponse
	}

	return pbToSCT(response)
}

func (sac StorageAuthorityClientWrapper) CountFQDNSets(ctx context.Context, window time.Duration, domains []string) (int64, error) {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	windowNanos := window.Nanoseconds()

	response, err := sac.inner.CountFQDNSets(localCtx, &sapb.CountFQDNSetsRequest{
		Window:  &windowNanos,
		Domains: domains,
	})
	if err != nil {
		return 0, unwrapError(err)
	}

	if response == nil || response.Count == nil {
		return 0, errIncompleteResponse
	}

	return *response.Count, nil
}

func (sac StorageAuthorityClientWrapper) FQDNSetExists(ctx context.Context, domains []string) (bool, error) {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	response, err := sac.inner.FQDNSetExists(localCtx, &sapb.FQDNSetExistsRequest{Domains: domains})
	if err != nil {
		return false, unwrapError(err)
	}

	if response == nil || response.Exists == nil {
		return false, errIncompleteResponse
	}

	return *response.Exists, nil
}

func (sac StorageAuthorityClientWrapper) NewRegistration(ctx context.Context, reg core.Registration) (core.Registration, error) {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	regPB, err := registrationToPB(reg)
	if err != nil {
		return core.Registration{}, err
	}

	response, err := sac.inner.NewRegistration(localCtx, regPB)
	if err != nil {
		return core.Registration{}, unwrapError(err)
	}

	if response == nil || !registrationValid(response) {
		return core.Registration{}, errIncompleteResponse
	}

	return pbToRegistration(response)
}

func (sac StorageAuthorityClientWrapper) UpdateRegistration(ctx context.Context, reg core.Registration) error {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	regPB, err := registrationToPB(reg)
	if err != nil {
		return err
	}

	_, err = sac.inner.UpdateRegistration(localCtx, regPB)
	if err != nil {
		return unwrapError(err)
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) NewPendingAuthorization(ctx context.Context, authz core.Authorization) (core.Authorization, error) {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	authPB, err := authzToPB(authz)
	if err != nil {
		return core.Authorization{}, err
	}

	response, err := sac.inner.NewPendingAuthorization(localCtx, authPB)
	if err != nil {
		return core.Authorization{}, unwrapError(err)
	}

	if response == nil || !authorizationValid(response) {
		return core.Authorization{}, errIncompleteResponse
	}

	return pbToAuthz(response)
}

func (sac StorageAuthorityClientWrapper) UpdatePendingAuthorization(ctx context.Context, authz core.Authorization) error {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	authPB, err := authzToPB(authz)
	if err != nil {
		return err
	}

	_, err = sac.inner.UpdatePendingAuthorization(localCtx, authPB)
	if err != nil {
		return unwrapError(err)
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) FinalizeAuthorization(ctx context.Context, authz core.Authorization) error {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	authPB, err := authzToPB(authz)
	if err != nil {
		return err
	}

	_, err = sac.inner.FinalizeAuthorization(localCtx, authPB)
	if err != nil {
		return unwrapError(err)
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) MarkCertificateRevoked(ctx context.Context, serial string, reasonCode revocation.Reason) error {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	reason := int64(reasonCode)

	_, err := sac.inner.MarkCertificateRevoked(localCtx, &sapb.MarkCertificateRevokedRequest{
		Serial: &serial,
		Code:   &reason,
	})
	if err != nil {
		return unwrapError(err)
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) AddCertificate(ctx context.Context, der []byte, regID int64) (string, error) {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	response, err := sac.inner.AddCertificate(localCtx, &corepb.CertificateRequest{
		Csr:   der,
		RegID: &regID,
	})
	if err != nil {
		return "", unwrapError(err)
	}

	if response == nil || response.Digest == nil {
		return "", errIncompleteResponse
	}

	return *response.Digest, nil
}

func (sac StorageAuthorityClientWrapper) AddSCTReceipt(ctx context.Context, sct core.SignedCertificateTimestamp) error {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	sctPB, err := sctToPB(sct)
	if err != nil {
		return err
	}

	_, err = sac.inner.AddSCTReceipt(localCtx, sctPB)
	if err != nil {
		return unwrapError(err)
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) RevokeAuthorizationsByDomain(ctx context.Context, domain core.AcmeIdentifier) (int64, int64, error) {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	response, err := sac.inner.RevokeAuthorizationsByDomain(localCtx, &sapb.RevokeAuthorizationsByDomainRequest{Domain: &domain.Value})
	if err != nil {
		return 0, 0, unwrapError(err)
	}

	if response == nil || response.Finalized == nil || response.Pending == nil {
		return 0, 0, errIncompleteResponse
	}

	return *response.Finalized, *response.Pending, nil
}

func (sac StorageAuthorityClientWrapper) DeactivateRegistration(ctx context.Context, id int64) error {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	_, err := sac.inner.DeactivateRegistration(localCtx, &sapb.RegistrationID{Id: &id})
	if err != nil {
		return unwrapError(err)
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) DeactivateAuthorization(ctx context.Context, id string) error {
	localCtx, cancel := context.WithTimeout(ctx, sac.timeout)
	defer cancel()

	_, err := sac.inner.DeactivateAuthorization(localCtx, &sapb.AuthorizationID{Id: &id})
	if err != nil {
		return unwrapError(err)
	}

	return nil
}

// StorageAuthorityServerWrapper is the gRPC version of a core.ServerAuthority server
type StorageAuthorityServerWrapper struct {
	inner core.StorageAuthority
}

func NewStorageAuthorityServer(inner core.StorageAuthority) *StorageAuthorityServerWrapper {
	return &StorageAuthorityServerWrapper{inner}
}
