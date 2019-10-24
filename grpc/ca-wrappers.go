// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wrappers wraps the GRPC calls in the core interfaces.
package grpc

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc"

	caPB "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/revocation"
)

// CertificateAuthorityClientWrapper is the gRPC version of a
// core.CertificateAuthority client. It composites a CertificateAuthorityClient
// and OCSPGeneratorClient, either of which may be nil if the calling code
// doesn't intend to use the relevant functions. Once we've fully moved to gRPC,
// calling code will do away with this wrapper and directly instantiate exactly
// the type of client it needs.
type CertificateAuthorityClientWrapper struct {
	inner     caPB.CertificateAuthorityClient
	innerOCSP caPB.OCSPGeneratorClient
}

func NewCertificateAuthorityClient(inner caPB.CertificateAuthorityClient, innerOCSP caPB.OCSPGeneratorClient) *CertificateAuthorityClientWrapper {
	return &CertificateAuthorityClientWrapper{inner, innerOCSP}
}

func (cac CertificateAuthorityClientWrapper) IssuePrecertificate(ctx context.Context, issueReq *caPB.IssueCertificateRequest) (*caPB.IssuePrecertificateResponse, error) {
	if cac.inner == nil {
		return nil, errors.New("this CA client does not support issuing precertificates")
	}
	resp, err := cac.inner.IssuePrecertificate(ctx, issueReq)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.DER == nil {
		return nil, errIncompleteResponse
	}
	return resp, nil
}

func (cac CertificateAuthorityClientWrapper) IssueCertificateForPrecertificate(ctx context.Context, req *caPB.IssueCertificateForPrecertificateRequest) (core.Certificate, error) {
	if cac.inner == nil {
		return core.Certificate{}, errors.New("this CA client does not support issuing precertificates")
	}
	res, err := cac.inner.IssueCertificateForPrecertificate(ctx, req)
	if err != nil {
		return core.Certificate{}, err
	}
	return PBToCert(res)
}

func (cac CertificateAuthorityClientWrapper) GenerateOCSP(ctx context.Context, ocspReq core.OCSPSigningRequest) ([]byte, error) {
	var inner interface {
		GenerateOCSP(context.Context, *caPB.GenerateOCSPRequest, ...grpc.CallOption) (*caPB.OCSPResponse, error)
	}
	if cac.innerOCSP == nil {
		inner = cac.inner
	} else {
		inner = cac.innerOCSP
	}
	reason := int32(ocspReq.Reason)
	revokedAt := ocspReq.RevokedAt.UnixNano()
	res, err := inner.GenerateOCSP(ctx, &caPB.GenerateOCSPRequest{
		CertDER:   ocspReq.CertDER,
		Status:    &ocspReq.Status,
		Reason:    &reason,
		RevokedAt: &revokedAt,
	})
	if err != nil {
		return nil, err
	}
	if res == nil || res.Response == nil {
		return nil, errIncompleteResponse
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

func (cas *CertificateAuthorityServerWrapper) IssuePrecertificate(ctx context.Context, request *caPB.IssueCertificateRequest) (*caPB.IssuePrecertificateResponse, error) {
	if request == nil || request.Csr == nil || request.OrderID == nil || request.RegistrationID == nil {
		return nil, errIncompleteRequest
	}
	return cas.inner.IssuePrecertificate(ctx, request)
}

func (cas *CertificateAuthorityServerWrapper) IssueCertificateForPrecertificate(ctx context.Context, req *caPB.IssueCertificateForPrecertificateRequest) (*corepb.Certificate, error) {
	if req == nil || req.DER == nil || req.OrderID == nil || req.RegistrationID == nil || req.SCTs == nil {
		return nil, errIncompleteRequest
	}
	cert, err := cas.inner.IssueCertificateForPrecertificate(ctx, req)
	if err != nil {
		return nil, err
	}
	return CertToPB(cert), nil
}

func (cas *CertificateAuthorityServerWrapper) GenerateOCSP(ctx context.Context, req *caPB.GenerateOCSPRequest) (*caPB.OCSPResponse, error) {
	if req.CertDER == nil || req.Status == nil || req.Reason == nil || req.RevokedAt == nil {
		return nil, errIncompleteRequest
	}
	res, err := cas.inner.GenerateOCSP(ctx, core.OCSPSigningRequest{
		CertDER:   req.CertDER,
		Status:    *req.Status,
		Reason:    revocation.Reason(*req.Reason),
		RevokedAt: time.Unix(0, *req.RevokedAt),
	})
	if err != nil {
		return nil, err
	}
	return &caPB.OCSPResponse{Response: res}, nil
}
