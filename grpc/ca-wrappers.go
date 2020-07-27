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
	return cac.inner.IssuePrecertificate(ctx, issueReq)
}

func (cac CertificateAuthorityClientWrapper) IssueCertificateForPrecertificate(ctx context.Context, req *capb.IssueCertificateForPrecertificateRequest) (*corepb.Certificate, error) {
	return cac.inner.IssueCertificateForPrecertificate(ctx, req)
}

func (cac CertificateAuthorityClientWrapper) GenerateOCSP(ctx context.Context, req *capb.GenerateOCSPRequest) (*capb.OCSPResponse, error) {
	return cac.inner.GenerateOCSP(ctx, req)
}

type OCSPGeneratorClientWrapper struct {
	inner capb.OCSPGeneratorClient
}

func NewOCSPGeneratorClient(inner capb.OCSPGeneratorClient) *OCSPGeneratorClientWrapper {
	return &OCSPGeneratorClientWrapper{inner}
}

func (ogc OCSPGeneratorClientWrapper) GenerateOCSP(ctx context.Context, req *capb.GenerateOCSPRequest, _ ...grpc.CallOption) (*capb.OCSPResponse, error) {
	return ogc.inner.GenerateOCSP(ctx, req)
}

// CertificateAuthorityServerWrapper is the gRPC version of a core.CertificateAuthority server
type CertificateAuthorityServerWrapper struct {
	inner core.CertificateAuthority
}

func NewCertificateAuthorityServer(inner core.CertificateAuthority) *CertificateAuthorityServerWrapper {
	return &CertificateAuthorityServerWrapper{inner}
}

func (cas *CertificateAuthorityServerWrapper) IssuePrecertificate(ctx context.Context, request *capb.IssueCertificateRequest) (*capb.IssuePrecertificateResponse, error) {
	return cas.inner.IssuePrecertificate(ctx, request)
}

func (cas *CertificateAuthorityServerWrapper) IssueCertificateForPrecertificate(ctx context.Context, req *capb.IssueCertificateForPrecertificateRequest) (*corepb.Certificate, error) {
	return cas.inner.IssueCertificateForPrecertificate(ctx, req)
}

func (cas *CertificateAuthorityServerWrapper) GenerateOCSP(ctx context.Context, req *capb.GenerateOCSPRequest) (*capb.OCSPResponse, error) {
	return cas.inner.GenerateOCSP(ctx, req)
}
