// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wrappers wraps the GRPC calls in the core interfaces.
package grpc

import (
	"errors"
	"time"

	"golang.org/x/net/context"
	ggrpc "google.golang.org/grpc"

	caPB "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/publisher"
	pubPB "github.com/letsencrypt/boulder/publisher/proto"
	vaPB "github.com/letsencrypt/boulder/va/proto"
)

type ValidationAuthorityGRPCServer struct {
	impl core.ValidationAuthority
}

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

func (cac CertificateAuthorityClientWrapper) IssueCertificate(ctx context.Context, csr x509.CertificateRequest, regID int64) (core.Certificate, error) {
	localCtx, cancel := context.WithTimeout(ctx, cac.timeout)
	defer cancel()
	res, err := cac.inner.IssueCertificate(localCtx, &caPB.IssueCertificateRequest{
		CSR:            csr.Raw,
		RegistrationID: regID,
	})
	if err != nil {
		return nil, err
	}
	return core.Certificate{
		RegistrationID: res.RegistrationID,
		Serial:         res.Serial,
		Digest:         res.Digest,
		DER:            res.DER,
		Issued:         time.Unix(0, res.Issued),
		Expires:        time.Unix(0, res.Expires),
	}, nil
}

func (cac CertificateAuthorityClientWrapper) GenerateOCSP(ctx context.Context, ocspReq core.OCSPSigningRequest) ([]bytes, error) {
	localCtx, cancel := context.WithTimeout(ctx, cac.timeout)
	defer cancel()
	res, err := cac.inner.GenerateOCSP(localCtx, &caPB.GenerateOCSPRequest{
		CertDER:   ocspReq.CertDER,
		Status:    ocspReq.Status,
		Reason:    ocspReq.Reason,
		RevokedAt: ocspReq.RevokedAt.UnixNano(),
	})
	if err != nil {
		return nil, err
	}
	return res.Response, nil
}

// CertificateAuthorityServerWrapper is the gRPC version of a core.CertificateAuthority server
type CertificateAuthorityServerWrapper struct {
	inner *core.CertificateAuthority
}

func (cas *CertificateAuthorityServerWrapper) IssueCertificatee(ctx context.Context, request *caPB.IssueCertificateRequest) (*caPB.Certificate, error) {
	res, err := cas.inner.IssueCertificate(ctx, request.CSR, request.RegistrationID)
	if err != nil {
		return nil, err
	}
	return &caPB.Certificate{
		RegistrationID: res.RegistrationID,
		Serial:         res.Serial,
		Digest:         res.Digest,
		DER:            res.DER,
		Issued:         res.Issued.UnixNano(),
		Expires:        res.Expires.UnixNano(),
	}, nil
}

func (cas *CertificateAuthorityServerWrapper) GenerateOCSP(ctx context.Context, request *caPB.GenerateOCSPRequest) (*caPB.OCSPResponse, error) {
	res, err := cas.inner.GenerateOCSP(ctx, core.OCSPSigningRequest{
		CertDER:   request.CertDER,
		Status:    request.Status,
		Reason:    request.Reason,
		RevokedAt: time.Unix(0, request.RevokedAt),
	})
	if err != nil {
		return nil, err
	}
	return &caPB.OCSPResponse{Response: res}, nil
}
