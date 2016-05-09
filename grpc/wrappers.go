// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wrappers wraps the GRPC calls in the core interfaces.
package grpc

import (
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/probs"
	"golang.org/x/net/context"
	ggrpc "google.golang.org/grpc"

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
	prob, ok := err.(*probs.ProblemDetails)
	if !ok {
		return nil, err
	}
	return validationResultToPB(records, prob)
}

func (s *ValidationAuthorityGRPCServer) IsSafeDomain(ctx context.Context, in *vaPB.IsSafeDomainRequest) (*vaPB.IsDomainSafe, error) {
	if in == nil {
		return nil, ErrMissingParameters
	}
	if in.Domain == nil {
		return nil, ErrMissingParameters
	}

	resp, err := s.impl.IsSafeDomain(ctx, *in.Domain)
	if err != nil {
		return nil, err
	}
	return &vaPB.IsDomainSafe{Valid: &resp}, nil
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

func (vac ValidationAuthorityGRPCClient) UpdateValidations(ctx context.Context, authz core.Authorization, index int) error {
	panic("UpdateValidations should not be called on VA GRPC client")
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
func (vac ValidationAuthorityGRPCClient) IsSafeDomain(ctx context.Context, domain string) (isSafe bool, err error) {
	valid, err := vac.gc.IsSafeDomain(ctx, &vaPB.IsSafeDomainRequest{Domain: &domain})
	if err != nil {
		return false, err
	}

	if valid == nil || (*valid).Valid == nil {
		return false, ErrMissingParameters
	}
	return *(*valid).Valid, nil
}
