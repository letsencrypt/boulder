// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wrappers wraps the GRPC calls in the core interfaces.
package grpc

import (
	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/publisher"
	pubpb "github.com/letsencrypt/boulder/publisher/proto"
)

// PublisherClientWrapper is a wrapper needed to satisfy the interfaces
// in core/interfaces.go
type PublisherClientWrapper struct {
	inner pubpb.PublisherClient
}

// NewPublisherClientWrapper returns an initialized PublisherClientWrapper
func NewPublisherClientWrapper(inner pubpb.PublisherClient) *PublisherClientWrapper {
	return &PublisherClientWrapper{inner}
}

// SubmitToSingleCTWithResult is a wrapper
func (pc *PublisherClientWrapper) SubmitToSingleCTWithResult(ctx context.Context, req *pubpb.Request) (*pubpb.Result, error) {
	res, err := pc.inner.SubmitToSingleCTWithResult(ctx, req)
	if err != nil {
		return nil, err
	}
	if res.Sct == nil {
		return nil, errIncompleteResponse
	}
	return res, nil
}

// PublisherServerWrapper is the gRPC version of a core.Publisher
type PublisherServerWrapper struct {
	inner *publisher.Impl
}

// NewPublisherServerWrapper returns an initialized PublisherServerWrapper
func NewPublisherServerWrapper(inner *publisher.Impl) *PublisherServerWrapper {
	return &PublisherServerWrapper{inner}
}

// SubmitToSingleCTWithResult is a wrapper
func (pub *PublisherServerWrapper) SubmitToSingleCTWithResult(ctx context.Context, req *pubpb.Request) (*pubpb.Result, error) {
	if req == nil || req.Der == nil || req.LogURL == nil || req.LogPublicKey == nil {
		return nil, errIncompleteRequest
	}
	return pub.inner.SubmitToSingleCTWithResult(ctx, req)
}
