// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wrappers wraps the GRPC calls in the core interfaces.
package grpc

import (
	"context"

	ggrpc "google.golang.org/grpc"

	vapb "github.com/letsencrypt/boulder/va/proto"
)

type ValidationAuthorityGRPCServer struct {
	inner vapb.VAServer
}

func (s *ValidationAuthorityGRPCServer) PerformValidation(ctx context.Context, req *vapb.PerformValidationRequest) (*vapb.ValidationResult, error) {
	return s.inner.PerformValidation(ctx, req)
}

func RegisterValidationAuthorityGRPCServer(s *ggrpc.Server, inner vapb.VAServer) error {
	rpcSrv := &ValidationAuthorityGRPCServer{inner}
	vapb.RegisterVAServer(s, rpcSrv)
	return nil
}

type ValidationAuthorityGRPCClient struct {
	inner vapb.VAClient
}

func NewValidationAuthorityGRPCClient(cc *ggrpc.ClientConn) vapb.VAClient {
	return &ValidationAuthorityGRPCClient{vapb.NewVAClient(cc)}
}

// PerformValidation has the VA revalidate the specified challenge and returns
// the updated Challenge object.
func (vac ValidationAuthorityGRPCClient) PerformValidation(ctx context.Context, req *vapb.PerformValidationRequest, opts ...ggrpc.CallOption) (*vapb.ValidationResult, error) {
	return vac.inner.PerformValidation(ctx, req)
}
