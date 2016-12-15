// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wrappers wraps the GRPC calls in the core interfaces.
package grpc

import (
	"errors"

	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/publisher"
	pubPB "github.com/letsencrypt/boulder/publisher/proto"
)

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

// SubmitToSingleCT makes a call to the gRPC version of the publisher to send
// the provided certificate to the log specified by log URI and public key
func (pc *PublisherClientWrapper) SubmitToSingleCT(ctx context.Context, logURL, logPublicKey string, der []byte) error {
	_, err := pc.inner.SubmitToSingleCT(
		ctx,
		&pubPB.Request{
			LogURL:       &logURL,
			LogPublicKey: &logPublicKey,
			Der:          der})
	return unwrapError(err)
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

func (pub *PublisherServerWrapper) SubmitToSingleCT(ctx context.Context, request *pubPB.Request) (*pubPB.Empty, error) {
	if request == nil || request.Der == nil || request.LogURL == nil || request.LogPublicKey == nil {
		return nil, errors.New("incomplete SubmitToSingleCT gRPC message")
	}
	err := wrapError(pub.inner.SubmitToSingleCT(ctx, *request.LogURL, *request.LogPublicKey, request.Der))
	return &pubPB.Empty{}, err
}
