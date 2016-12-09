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
	inner pubPB.PublisherClient
}

// NewPublisherClientWrapper returns an initialized PublisherClientWrapper
func NewPublisherClientWrapper(inner pubPB.PublisherClient) *PublisherClientWrapper {
	return &PublisherClientWrapper{inner}
}

// SubmitToCT makes a call to the gRPC version of the publisher
func (pc *PublisherClientWrapper) SubmitToCT(ctx context.Context, der []byte) error {
	_, err := pc.inner.SubmitToCT(ctx, &pubPB.Request{Der: der})
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
	inner caPB.CertificateAuthorityClient
}

func NewCertificateAuthorityClient(inner caPB.CertificateAuthorityClient) *CertificateAuthorityClientWrapper {
	return &CertificateAuthorityClientWrapper{inner}
}

func (cac CertificateAuthorityClientWrapper) IssueCertificate(ctx context.Context, csr x509.CertificateRequest, regID int64) (core.Certificate, error) {
	res, err := cac.inner.IssueCertificate(ctx, &caPB.IssueCertificateRequest{
		Csr:            csr.Raw,
		RegistrationID: &regID,
	})
	if err != nil {
		return core.Certificate{}, err
	}
	return pbToCert(res), nil
}

func (cac CertificateAuthorityClientWrapper) GenerateOCSP(ctx context.Context, ocspReq core.OCSPSigningRequest) ([]byte, error) {
	reason := int32(ocspReq.Reason)
	revokedAt := ocspReq.RevokedAt.UnixNano()
	res, err := cac.inner.GenerateOCSP(ctx, &caPB.GenerateOCSPRequest{
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
	cert, err := cas.inner.IssueCertificate(ctx, *csr, *request.RegistrationID)
	if err != nil {
		return nil, err
	}
	return certToPB(cert), nil
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
	inner rapb.RegistrationAuthorityClient
}

func NewRegistrationAuthorityClient(inner rapb.RegistrationAuthorityClient) *RegistrationAuthorityClientWrapper {
	return &RegistrationAuthorityClientWrapper{inner}
}

func (rac RegistrationAuthorityClientWrapper) NewRegistration(ctx context.Context, reg core.Registration) (core.Registration, error) {
	req, err := registrationToPB(reg)
	if err != nil {
		return core.Registration{}, err
	}

	response, err := rac.inner.NewRegistration(ctx, req)
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
	req, err := authzToPB(authz)
	if err != nil {
		return core.Authorization{}, err
	}

	response, err := rac.inner.NewAuthorization(ctx, &rapb.NewAuthorizationRequest{Authz: req, RegID: &regID})
	if err != nil {
		return core.Authorization{}, unwrapError(err)
	}

	if response == nil || !authorizationValid(response) {
		return core.Authorization{}, errIncompleteResponse
	}

	return pbToAuthz(response)
}

func (rac RegistrationAuthorityClientWrapper) NewCertificate(ctx context.Context, csr core.CertificateRequest, regID int64) (core.Certificate, error) {
	response, err := rac.inner.NewCertificate(ctx, &rapb.NewCertificateRequest{Csr: csr.Bytes, RegID: &regID})
	if err != nil {
		return core.Certificate{}, unwrapError(err)
	}

	if response == nil || !certificateValid(response) {
		return core.Certificate{}, errIncompleteResponse
	}

	return pbToCert(response), nil
}

func (rac RegistrationAuthorityClientWrapper) UpdateRegistration(ctx context.Context, base, updates core.Registration) (core.Registration, error) {
	basePB, err := registrationToPB(base)
	if err != nil {
		return core.Registration{}, err
	}
	updatePB, err := registrationToPB(updates)
	if err != nil {
		return core.Registration{}, err
	}

	response, err := rac.inner.UpdateRegistration(ctx, &rapb.UpdateRegistrationRequest{Base: basePB, Update: updatePB})
	if err != nil {
		return core.Registration{}, unwrapError(err)
	}

	if response == nil || !registrationValid(response) {
		return core.Registration{}, errIncompleteResponse
	}

	return pbToRegistration(response)
}

func (rac RegistrationAuthorityClientWrapper) UpdateAuthorization(ctx context.Context, authz core.Authorization, challengeIndex int, chall core.Challenge) (core.Authorization, error) {
	authzPB, err := authzToPB(authz)
	if err != nil {
		return core.Authorization{}, err
	}
	challPB, err := challengeToPB(chall)
	if err != nil {
		return core.Authorization{}, err
	}

	ind := int64(challengeIndex)

	response, err := rac.inner.UpdateAuthorization(ctx, &rapb.UpdateAuthorizationRequest{
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
	reason := int64(code)
	_, err := rac.inner.RevokeCertificateWithReg(ctx, &rapb.RevokeCertificateWithRegRequest{
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
	regPB, err := registrationToPB(reg)
	if err != nil {
		return err
	}

	_, err = rac.inner.DeactivateRegistration(ctx, regPB)
	if err != nil {
		return unwrapError(err)
	}

	return nil
}

func (rac RegistrationAuthorityClientWrapper) DeactivateAuthorization(ctx context.Context, auth core.Authorization) error {
	authzPB, err := authzToPB(auth)
	if err != nil {
		return err
	}

	_, err = rac.inner.DeactivateAuthorization(ctx, authzPB)
	if err != nil {
		return unwrapError(err)
	}

	return nil
}

func (rac RegistrationAuthorityClientWrapper) AdministrativelyRevokeCertificate(ctx context.Context, cert x509.Certificate, code revocation.Reason, adminName string) error {
	reason := int64(code)
	_, err := rac.inner.AdministrativelyRevokeCertificate(ctx, &rapb.AdministrativelyRevokeCertificateRequest{
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
	return certToPB(cert), nil
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
	inner sapb.StorageAuthorityClient
}

func NewStorageAuthorityClient(inner sapb.StorageAuthorityClient) *StorageAuthorityClientWrapper {
	return &StorageAuthorityClientWrapper{inner}
}

func (sac StorageAuthorityClientWrapper) GetRegistration(ctx context.Context, regID int64) (core.Registration, error) {
	response, err := sac.inner.GetRegistration(ctx, &sapb.RegistrationID{Id: &regID})
	if err != nil {
		return core.Registration{}, unwrapError(err)
	}

	if response == nil || !registrationValid(response) {
		return core.Registration{}, errIncompleteResponse
	}

	return pbToRegistration(response)
}

func (sac StorageAuthorityClientWrapper) GetRegistrationByKey(ctx context.Context, key *jose.JsonWebKey) (core.Registration, error) {
	keyBytes, err := key.MarshalJSON()
	if err != nil {
		return core.Registration{}, err
	}

	response, err := sac.inner.GetRegistrationByKey(ctx, &sapb.JsonWebKey{Jwk: keyBytes})
	if err != nil {
		return core.Registration{}, unwrapError(err)
	}

	if response == nil || !registrationValid(response) {
		return core.Registration{}, errIncompleteResponse
	}

	return pbToRegistration(response)
}

func (sac StorageAuthorityClientWrapper) GetAuthorization(ctx context.Context, authID string) (core.Authorization, error) {
	response, err := sac.inner.GetAuthorization(ctx, &sapb.AuthorizationID{Id: &authID})
	if err != nil {
		return core.Authorization{}, unwrapError(err)
	}

	if response == nil || !authorizationValid(response) {
		return core.Authorization{}, errIncompleteResponse
	}

	return pbToAuthz(response)
}

func (sac StorageAuthorityClientWrapper) GetValidAuthorizations(ctx context.Context, regID int64, domains []string, now time.Time) (map[string]*core.Authorization, error) {
	nowUnix := now.UnixNano()

	response, err := sac.inner.GetValidAuthorizations(ctx, &sapb.GetValidAuthorizationsRequest{
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
	response, err := sac.inner.GetCertificate(ctx, &sapb.Serial{Serial: &serial})
	if err != nil {
		return core.Certificate{}, unwrapError(err)
	}

	if response == nil || !certificateValid(response) {
		return core.Certificate{}, errIncompleteResponse
	}

	return pbToCert(response), nil
}

func (sac StorageAuthorityClientWrapper) GetCertificateStatus(ctx context.Context, serial string) (core.CertificateStatus, error) {
	response, err := sac.inner.GetCertificateStatus(ctx, &sapb.Serial{Serial: &serial})
	if err != nil {
		return core.CertificateStatus{}, unwrapError(err)
	}

	if response == nil || response.Serial == nil || response.SubscriberApproved == nil || response.Status == nil || response.OcspLastUpdated == nil || response.RevokedDate == nil || response.RevokedReason == nil || response.LastExpirationNagSent == nil || response.OcspResponse == nil || response.NotAfter == nil || response.IsExpired == nil {
		return core.CertificateStatus{}, errIncompleteResponse
	}

	return core.CertificateStatus{
		Serial:                *response.Serial,
		SubscriberApproved:    *response.SubscriberApproved,
		Status:                core.OCSPStatus(*response.Status),
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
	earliestNano := earliest.UnixNano()
	latestNano := latest.UnixNano()

	response, err := sac.inner.CountCertificatesRange(ctx, &sapb.Range{
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
	earliestNano := earliest.UnixNano()
	latestNano := latest.UnixNano()

	response, err := sac.inner.CountCertificatesByNames(ctx, &sapb.CountCertificatesByNamesRequest{
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
	earliestNano := earliest.UnixNano()
	latestNano := latest.UnixNano()

	response, err := sac.inner.CountRegistrationsByIP(ctx, &sapb.CountRegistrationsByIPRequest{
		Range: &sapb.Range{
			Earliest: &earliestNano,
			Latest:   &latestNano,
		},
		Ip: ip,
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
	response, err := sac.inner.CountPendingAuthorizations(ctx, &sapb.RegistrationID{Id: &regID})
	if err != nil {
		return 0, unwrapError(err)
	}

	if response == nil || response.Count == nil {
		return 0, errIncompleteResponse
	}

	return int(*response.Count), nil
}

func (sac StorageAuthorityClientWrapper) GetSCTReceipt(ctx context.Context, serial, logID string) (core.SignedCertificateTimestamp, error) {
	response, err := sac.inner.GetSCTReceipt(ctx, &sapb.GetSCTReceiptRequest{Serial: &serial, LogID: &logID})
	if err != nil {
		return core.SignedCertificateTimestamp{}, unwrapError(err)
	}

	if response == nil || !sctValid(response) {
		return core.SignedCertificateTimestamp{}, errIncompleteResponse
	}

	return pbToSCT(response), nil
}

func (sac StorageAuthorityClientWrapper) CountFQDNSets(ctx context.Context, window time.Duration, domains []string) (int64, error) {
	windowNanos := window.Nanoseconds()

	response, err := sac.inner.CountFQDNSets(ctx, &sapb.CountFQDNSetsRequest{
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
	response, err := sac.inner.FQDNSetExists(ctx, &sapb.FQDNSetExistsRequest{Domains: domains})
	if err != nil {
		return false, unwrapError(err)
	}

	if response == nil || response.Exists == nil {
		return false, errIncompleteResponse
	}

	return *response.Exists, nil
}

func (sac StorageAuthorityClientWrapper) NewRegistration(ctx context.Context, reg core.Registration) (core.Registration, error) {
	regPB, err := registrationToPB(reg)
	if err != nil {
		return core.Registration{}, err
	}

	response, err := sac.inner.NewRegistration(ctx, regPB)
	if err != nil {
		return core.Registration{}, unwrapError(err)
	}

	if response == nil || !registrationValid(response) {
		return core.Registration{}, errIncompleteResponse
	}

	return pbToRegistration(response)
}

func (sac StorageAuthorityClientWrapper) UpdateRegistration(ctx context.Context, reg core.Registration) error {
	regPB, err := registrationToPB(reg)
	if err != nil {
		return err
	}

	_, err = sac.inner.UpdateRegistration(ctx, regPB)
	if err != nil {
		return unwrapError(err)
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) NewPendingAuthorization(ctx context.Context, authz core.Authorization) (core.Authorization, error) {
	authPB, err := authzToPB(authz)
	if err != nil {
		return core.Authorization{}, err
	}

	response, err := sac.inner.NewPendingAuthorization(ctx, authPB)
	if err != nil {
		return core.Authorization{}, unwrapError(err)
	}

	if response == nil || !authorizationValid(response) {
		return core.Authorization{}, errIncompleteResponse
	}

	return pbToAuthz(response)
}

func (sac StorageAuthorityClientWrapper) UpdatePendingAuthorization(ctx context.Context, authz core.Authorization) error {
	authPB, err := authzToPB(authz)
	if err != nil {
		return err
	}

	_, err = sac.inner.UpdatePendingAuthorization(ctx, authPB)
	if err != nil {
		return unwrapError(err)
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) FinalizeAuthorization(ctx context.Context, authz core.Authorization) error {
	authPB, err := authzToPB(authz)
	if err != nil {
		return err
	}

	_, err = sac.inner.FinalizeAuthorization(ctx, authPB)
	if err != nil {
		return unwrapError(err)
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) MarkCertificateRevoked(ctx context.Context, serial string, reasonCode revocation.Reason) error {
	reason := int64(reasonCode)

	_, err := sac.inner.MarkCertificateRevoked(ctx, &sapb.MarkCertificateRevokedRequest{
		Serial: &serial,
		Code:   &reason,
	})
	if err != nil {
		return unwrapError(err)
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) AddCertificate(ctx context.Context, der []byte, regID int64) (string, error) {
	response, err := sac.inner.AddCertificate(ctx, &sapb.AddCertificateRequest{
		Der:   der,
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
	_, err := sac.inner.AddSCTReceipt(ctx, sctToPB(sct))
	if err != nil {
		return unwrapError(err)
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) RevokeAuthorizationsByDomain(ctx context.Context, domain core.AcmeIdentifier) (int64, int64, error) {
	response, err := sac.inner.RevokeAuthorizationsByDomain(ctx, &sapb.RevokeAuthorizationsByDomainRequest{Domain: &domain.Value})
	if err != nil {
		return 0, 0, unwrapError(err)
	}

	if response == nil || response.Finalized == nil || response.Pending == nil {
		return 0, 0, errIncompleteResponse
	}

	return *response.Finalized, *response.Pending, nil
}

func (sac StorageAuthorityClientWrapper) DeactivateRegistration(ctx context.Context, id int64) error {
	_, err := sac.inner.DeactivateRegistration(ctx, &sapb.RegistrationID{Id: &id})
	if err != nil {
		return unwrapError(err)
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) DeactivateAuthorization(ctx context.Context, id string) error {
	_, err := sac.inner.DeactivateAuthorization(ctx, &sapb.AuthorizationID{Id: &id})
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

func (sas StorageAuthorityServerWrapper) GetRegistration(ctx context.Context, request *sapb.RegistrationID) (*corepb.Registration, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	reg, err := sas.inner.GetRegistration(ctx, *request.Id)
	if err != nil {
		return nil, wrapError(err)
	}

	return registrationToPB(reg)
}

func (sas StorageAuthorityServerWrapper) GetRegistrationByKey(ctx context.Context, request *sapb.JsonWebKey) (*corepb.Registration, error) {
	if request == nil || request.Jwk == nil {
		return nil, errIncompleteRequest
	}

	var jwk jose.JsonWebKey
	err := jwk.UnmarshalJSON(request.Jwk)
	if err != nil {
		return nil, err
	}

	reg, err := sas.inner.GetRegistrationByKey(ctx, &jwk)
	if err != nil {
		return nil, wrapError(err)
	}

	return registrationToPB(reg)
}

func (sas StorageAuthorityServerWrapper) GetAuthorization(ctx context.Context, request *sapb.AuthorizationID) (*corepb.Authorization, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	authz, err := sas.inner.GetAuthorization(ctx, *request.Id)
	if err != nil {
		return nil, wrapError(err)
	}

	return authzToPB(authz)
}

func (sas StorageAuthorityServerWrapper) GetValidAuthorizations(ctx context.Context, request *sapb.GetValidAuthorizationsRequest) (*sapb.ValidAuthorizations, error) {
	if request == nil || request.RegistrationID == nil || request.Domains == nil || request.Now == nil {
		return nil, errIncompleteRequest
	}

	valid, err := sas.inner.GetValidAuthorizations(ctx, *request.RegistrationID, request.Domains, time.Unix(0, *request.Now))
	if err != nil {
		return nil, wrapError(err)
	}

	resp := &sapb.ValidAuthorizations{}
	for k, v := range valid {
		authzPB, err := authzToPB(*v)
		if err != nil {
			return nil, err
		}
		resp.Valid = append(resp.Valid, &sapb.ValidAuthorizations_MapElement{Domain: &k, Authz: authzPB})
	}

	return resp, nil
}

func (sas StorageAuthorityServerWrapper) GetCertificate(ctx context.Context, request *sapb.Serial) (*corepb.Certificate, error) {
	if request == nil || request.Serial == nil {
		return nil, errIncompleteRequest
	}

	cert, err := sas.inner.GetCertificate(ctx, *request.Serial)
	if err != nil {
		return nil, wrapError(err)
	}

	return certToPB(cert), nil
}

func (sas StorageAuthorityServerWrapper) GetCertificateStatus(ctx context.Context, request *sapb.Serial) (*sapb.CertificateStatus, error) {
	if request == nil || request.Serial == nil {
		return nil, errIncompleteRequest
	}

	certStatus, err := sas.inner.GetCertificateStatus(ctx, *request.Serial)
	if err != nil {
		return nil, wrapError(err)
	}

	ocspLastUpdatedNano := certStatus.OCSPLastUpdated.UnixNano()
	revokedDateNano := certStatus.RevokedDate.UnixNano()
	lastExpirationNagSentNano := certStatus.LastExpirationNagSent.UnixNano()
	notAfterNano := certStatus.NotAfter.UnixNano()
	reason := int64(certStatus.RevokedReason)
	status := string(certStatus.Status)

	return &sapb.CertificateStatus{
		Serial:                &certStatus.Serial,
		SubscriberApproved:    &certStatus.SubscriberApproved,
		Status:                &status,
		OcspLastUpdated:       &ocspLastUpdatedNano,
		RevokedDate:           &revokedDateNano,
		RevokedReason:         &reason,
		LastExpirationNagSent: &lastExpirationNagSentNano,
		OcspResponse:          certStatus.OCSPResponse,
		NotAfter:              &notAfterNano,
		IsExpired:             &certStatus.IsExpired,
	}, nil
}

func (sas StorageAuthorityServerWrapper) CountCertificatesRange(ctx context.Context, request *sapb.Range) (*sapb.Count, error) {
	if request == nil || request.Earliest == nil || request.Latest == nil {
		return nil, errIncompleteRequest
	}

	count, err := sas.inner.CountCertificatesRange(ctx, time.Unix(0, *request.Earliest), time.Unix(0, *request.Latest))
	if err != nil {
		return nil, wrapError(err)
	}

	return &sapb.Count{Count: &count}, nil
}

func (sas StorageAuthorityServerWrapper) CountCertificatesByNames(ctx context.Context, request *sapb.CountCertificatesByNamesRequest) (*sapb.CountByNames, error) {
	if request == nil || request.Range == nil || request.Range.Earliest == nil || request.Range.Latest == nil || request.Names == nil {
		return nil, errIncompleteRequest
	}

	byNames, err := sas.inner.CountCertificatesByNames(ctx, request.Names, time.Unix(0, *request.Range.Earliest), time.Unix(0, *request.Range.Latest))
	if err != nil {
		return nil, wrapError(err)
	}

	resp := &sapb.CountByNames{}
	for k, v := range byNames {
		castedV := int64(v)
		resp.CountByNames = append(resp.CountByNames, &sapb.CountByNames_MapElement{Name: &k, Count: &castedV})
	}

	return resp, nil
}

func (sas StorageAuthorityServerWrapper) CountRegistrationsByIP(ctx context.Context, request *sapb.CountRegistrationsByIPRequest) (*sapb.Count, error) {
	if request == nil || request.Ip == nil || request.Range == nil || request.Range.Earliest == nil || request.Range.Latest == nil {
		return nil, errIncompleteRequest
	}

	count, err := sas.inner.CountRegistrationsByIP(ctx, net.IP(request.Ip), time.Unix(0, *request.Range.Earliest), time.Unix(0, *request.Range.Latest))
	if err != nil {
		return nil, wrapError(err)
	}

	castedCount := int64(count)
	return &sapb.Count{Count: &castedCount}, nil
}

func (sas StorageAuthorityServerWrapper) CountPendingAuthorizations(ctx context.Context, request *sapb.RegistrationID) (*sapb.Count, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	count, err := sas.inner.CountPendingAuthorizations(ctx, *request.Id)
	if err != nil {
		return nil, wrapError(err)
	}

	castedCount := int64(count)
	return &sapb.Count{Count: &castedCount}, nil
}

func (sas StorageAuthorityServerWrapper) GetSCTReceipt(ctx context.Context, request *sapb.GetSCTReceiptRequest) (*sapb.SignedCertificateTimestamp, error) {
	if request == nil || request.Serial == nil || request.LogID == nil {
		return nil, errIncompleteRequest
	}

	sct, err := sas.inner.GetSCTReceipt(ctx, *request.Serial, *request.LogID)
	if err != nil {
		return nil, wrapError(err)
	}

	return sctToPB(sct), nil
}

func (sas StorageAuthorityServerWrapper) CountFQDNSets(ctx context.Context, request *sapb.CountFQDNSetsRequest) (*sapb.Count, error) {
	if request == nil || request.Window == nil || request.Domains == nil {
		return nil, errIncompleteRequest
	}

	window := time.Duration(*request.Window)

	count, err := sas.inner.CountFQDNSets(ctx, window, request.Domains)
	if err != nil {
		return nil, wrapError(err)
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
		return nil, wrapError(err)
	}

	return &sapb.Exists{Exists: &exists}, nil
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
		return nil, wrapError(err)
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
		return nil, wrapError(err)
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) NewPendingAuthorization(ctx context.Context, request *corepb.Authorization) (*corepb.Authorization, error) {
	if request == nil || !authorizationValid(request) {
		return nil, errIncompleteRequest
	}

	authz, err := pbToAuthz(request)
	if err != nil {
		return nil, err
	}

	newAuthz, err := sas.inner.NewPendingAuthorization(ctx, authz)
	if err != nil {
		return nil, wrapError(err)
	}

	return authzToPB(newAuthz)
}

func (sas StorageAuthorityServerWrapper) UpdatePendingAuthorization(ctx context.Context, request *corepb.Authorization) (*corepb.Empty, error) {
	if request == nil || !authorizationValid(request) {
		return nil, errIncompleteRequest
	}

	authz, err := pbToAuthz(request)
	if err != nil {
		return nil, err
	}

	err = sas.inner.UpdatePendingAuthorization(ctx, authz)
	if err != nil {
		return nil, wrapError(err)
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) FinalizeAuthorization(ctx context.Context, request *corepb.Authorization) (*corepb.Empty, error) {
	if request == nil || !authorizationValid(request) {
		return nil, errIncompleteRequest
	}

	authz, err := pbToAuthz(request)
	if err != nil {
		return nil, err
	}

	err = sas.inner.FinalizeAuthorization(ctx, authz)
	if err != nil {
		return nil, wrapError(err)
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) MarkCertificateRevoked(ctx context.Context, request *sapb.MarkCertificateRevokedRequest) (*corepb.Empty, error) {
	if request == nil || request.Serial == nil || request.Code == nil {
		return nil, errIncompleteRequest
	}

	err := sas.inner.MarkCertificateRevoked(ctx, *request.Serial, revocation.Reason(*request.Code))
	if err != nil {
		return nil, wrapError(err)
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) AddCertificate(ctx context.Context, request *sapb.AddCertificateRequest) (*sapb.AddCertificateResponse, error) {
	if request == nil || request.Der == nil || request.RegID == nil {
		return nil, errIncompleteRequest
	}

	digest, err := sas.inner.AddCertificate(ctx, request.Der, *request.RegID)
	if err != nil {
		return nil, wrapError(err)
	}

	return &sapb.AddCertificateResponse{Digest: &digest}, nil
}

func (sas StorageAuthorityServerWrapper) AddSCTReceipt(ctx context.Context, request *sapb.SignedCertificateTimestamp) (*corepb.Empty, error) {
	if request == nil || !sctValid(request) {
		return nil, errIncompleteRequest
	}

	err := sas.inner.AddSCTReceipt(ctx, pbToSCT(request))
	if err != nil {
		return nil, wrapError(err)
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) RevokeAuthorizationsByDomain(ctx context.Context, request *sapb.RevokeAuthorizationsByDomainRequest) (*sapb.RevokeAuthorizationsByDomainResponse, error) {
	if request == nil || request.Domain == nil {
		return nil, errIncompleteRequest
	}

	finalized, pending, err := sas.inner.RevokeAuthorizationsByDomain(ctx, core.AcmeIdentifier{Value: *request.Domain, Type: core.IdentifierDNS})
	if err != nil {
		return nil, wrapError(err)
	}

	return &sapb.RevokeAuthorizationsByDomainResponse{Finalized: &finalized, Pending: &pending}, nil
}

func (sas StorageAuthorityServerWrapper) DeactivateRegistration(ctx context.Context, request *sapb.RegistrationID) (*corepb.Empty, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	err := sas.inner.DeactivateRegistration(ctx, *request.Id)
	if err != nil {
		return nil, wrapError(err)
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) DeactivateAuthorization(ctx context.Context, request *sapb.AuthorizationID) (*corepb.Empty, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	err := sas.inner.DeactivateAuthorization(ctx, *request.Id)
	if err != nil {
		return nil, wrapError(err)
	}

	return &corepb.Empty{}, nil
}
