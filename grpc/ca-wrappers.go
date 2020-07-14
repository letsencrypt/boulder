// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wrappers wraps the GRPC calls in the core interfaces.
package grpc

import (
	"context"

	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"google.golang.org/grpc"
)

type CertificateAuthorityClientWrapper struct {
	inner capb.CertificateAuthorityClient
}

func NewCertificateAuthorityClient(inner capb.CertificateAuthorityClient) *CertificateAuthorityClientWrapper {
	return &CertificateAuthorityClientWrapper{inner}
}

func (cac CertificateAuthorityClientWrapper) IssuePrecertificate(ctx context.Context, issueReq *capb.IssueCertificateRequest) (*capb.IssuePrecertificateResponse, error) {
	resp, err := cac.inner.IssuePrecertificate(ctx, issueReq)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.DER == nil {
		return nil, errIncompleteResponse
	}
	return resp, nil
}

func (cac CertificateAuthorityClientWrapper) IssueCertificateForPrecertificate(ctx context.Context, req *capb.IssueCertificateForPrecertificateRequest) (core.Certificate, error) {
	res, err := cac.inner.IssueCertificateForPrecertificate(ctx, req)
	if err != nil {
		return core.Certificate{}, err
	}
	return PBToCert(res)
}

func (cac CertificateAuthorityClientWrapper) GenerateOCSP(ctx context.Context, req *capb.GenerateOCSPRequest) (*capb.OCSPResponse, error) {
	res, err := cac.inner.GenerateOCSP(ctx, req)
	if err != nil {
		return nil, err
	}
	if res == nil || res.Response == nil {
		return nil, errIncompleteResponse
	}
	return res, nil
}

type OCSPGeneratorClientWrapper struct {
	inner capb.OCSPGeneratorClient
}

func NewOCSPGeneratorClient(inner capb.OCSPGeneratorClient) *OCSPGeneratorClientWrapper {
	return &OCSPGeneratorClientWrapper{inner}
}

func (ogc OCSPGeneratorClientWrapper) GenerateOCSP(ctx context.Context, req *capb.GenerateOCSPRequest, _ ...grpc.CallOption) (*capb.OCSPResponse, error) {
	res, err := ogc.inner.GenerateOCSP(ctx, req)
	if err != nil {
		return nil, err
	}
	if res == nil || res.Response == nil {
		return nil, errIncompleteResponse
	}
	return res, nil
}

// CertificateAuthorityServerWrapper is the gRPC version of a core.CertificateAuthority server
type CertificateAuthorityServerWrapper struct {
	inner core.CertificateAuthority
}

func NewCertificateAuthorityServer(inner core.CertificateAuthority) *CertificateAuthorityServerWrapper {
	return &CertificateAuthorityServerWrapper{inner}
}

func (cas *CertificateAuthorityServerWrapper) IssuePrecertificate(ctx context.Context, request *capb.IssueCertificateRequest) (*capb.IssuePrecertificateResponse, error) {
	if request == nil || request.Csr == nil {
		return nil, errIncompleteRequest
	}
	return cas.inner.IssuePrecertificate(ctx, request)
}

func (cas *CertificateAuthorityServerWrapper) IssueCertificateForPrecertificate(ctx context.Context, req *capb.IssueCertificateForPrecertificateRequest) (*corepb.Certificate, error) {
	if req == nil || req.DER == nil || req.SCTs == nil {
		return nil, errIncompleteRequest
	}
	cert, err := cas.inner.IssueCertificateForPrecertificate(ctx, req)
	if err != nil {
		return nil, err
	}
	return CertToPB(cert), nil
}

func (cas *CertificateAuthorityServerWrapper) GenerateOCSP(ctx context.Context, req *capb.GenerateOCSPRequest) (*capb.OCSPResponse, error) {
	if req.CertDER == nil && (req.Serial == "" || req.IssuerID == 0) {
		return nil, errIncompleteRequest
	}
	return cas.inner.GenerateOCSP(ctx, req)
}
