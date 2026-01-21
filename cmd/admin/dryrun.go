package main

import (
	"context"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/types/known/emptypb"

	blog "github.com/letsencrypt/boulder/log"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

var _ rapb.RegistrationAuthorityClient = (*dryRunRAC)(nil)

type dryRunRAC struct {
	rapb.RegistrationAuthorityClient
	log blog.Logger
}

func (d dryRunRAC) AdministrativelyRevokeCertificate(_ context.Context, req *rapb.AdministrativelyRevokeCertificateRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	b, err := prototext.Marshal(req)
	if err != nil {
		return nil, err
	}
	d.log.Infof("dry-run: %#v", string(b))
	return &emptypb.Empty{}, nil
}

var _ rapb.RegistrationAuthorityClient = (*dryRunRAC)(nil)

type dryRunSAC struct {
	sapb.StorageAuthorityClient
	log blog.Logger
}

func (d dryRunSAC) AddBlockedKey(_ context.Context, req *sapb.AddBlockedKeyRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	d.log.Infof("dry-run: Block SPKI hash %x by %s %s", req.KeyHash, req.Comment, req.Source)
	return &emptypb.Empty{}, nil
}

func (d dryRunSAC) AddRateLimitOverride(_ context.Context, req *sapb.AddRateLimitOverrideRequest, _ ...grpc.CallOption) (*sapb.AddRateLimitOverrideResponse, error) {
	b, err := prototext.Marshal(req)
	if err != nil {
		return nil, err
	}
	d.log.Infof("dry-run: %#v", string(b))
	return &sapb.AddRateLimitOverrideResponse{
		Inserted: true,
		Enabled:  true,
	}, nil
}

func (d dryRunSAC) DisableRateLimitOverride(_ context.Context, req *sapb.DisableRateLimitOverrideRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	b, err := prototext.Marshal(req)
	if err != nil {
		return nil, err
	}
	d.log.Infof("dry-run: %#v", string(b))
	return &emptypb.Empty{}, nil
}

func (d dryRunSAC) EnableRateLimitOverride(_ context.Context, req *sapb.EnableRateLimitOverrideRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	b, err := prototext.Marshal(req)
	if err != nil {
		return nil, err
	}
	d.log.Infof("dry-run: %#v", string(b))
	return &emptypb.Empty{}, nil
}

func (d dryRunSAC) GetEnabledRateLimitOverrides(ctx context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (grpc.ServerStreamingClient[sapb.RateLimitOverrideResponse], error) {
	d.log.Info("dry-run: GetEnabledRateLimitOverrides")
	return nil, errors.New("dry-run mode is not enabled for dump-limit-overrides")
}
