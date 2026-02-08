package main

import (
	"context"
	"encoding/hex"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/letsencrypt/boulder/blog"
	"github.com/letsencrypt/boulder/identifier"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type dryRunRAC struct{}

var _ adminRAClient = (*dryRunRAC)(nil)

func (d dryRunRAC) AdministrativelyRevokeCertificate(ctx context.Context, req *rapb.AdministrativelyRevokeCertificateRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	blog.Info(ctx, "Revoke certificate", blog.Serial(req.Serial), slog.Int64("reasonCode", req.Code))
	return &emptypb.Empty{}, nil
}

type dryRunSAC struct{}

var _ adminSAClient = (*dryRunSAC)(nil)

func (d dryRunSAC) AddBlockedKey(ctx context.Context, req *sapb.AddBlockedKeyRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	blog.Info(ctx, "Block SPKI hash",
		slog.String("keyHash", hex.EncodeToString(req.KeyHash)),
		slog.String("comment", req.Comment),
		slog.String("originator", req.Source))
	return &emptypb.Empty{}, nil
}

func (d dryRunSAC) AddRateLimitOverride(ctx context.Context, req *sapb.AddRateLimitOverrideRequest, _ ...grpc.CallOption) (*sapb.AddRateLimitOverrideResponse, error) {
	blog.Info(ctx, "Add override",
		slog.String("bucketKey", req.Override.BucketKey),
		slog.String("comment", req.Override.Comment))
	return &sapb.AddRateLimitOverrideResponse{Inserted: true, Enabled: true}, nil
}

func (d dryRunSAC) DisableRateLimitOverride(ctx context.Context, req *sapb.DisableRateLimitOverrideRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	blog.Info(ctx, "Disable override", slog.String("bucketKey", req.BucketKey))
	return &emptypb.Empty{}, nil
}

func (d dryRunSAC) EnableRateLimitOverride(ctx context.Context, req *sapb.EnableRateLimitOverrideRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	blog.Info(ctx, "Enable override", slog.String("bucketKey", req.BucketKey))
	return &emptypb.Empty{}, nil
}

func (d dryRunSAC) PauseIdentifiers(ctx context.Context, req *sapb.PauseRequest, _ ...grpc.CallOption) (*sapb.PauseIdentifiersResponse, error) {
	blog.Info(ctx, "Pause identifiers",
		blog.Acct(req.RegistrationID),
		blog.Idents(identifier.FromProtoSlice(req.Identifiers)))
	return &sapb.PauseIdentifiersResponse{Paused: int64(len(req.Identifiers))}, nil
}

func (d dryRunSAC) UnpauseAccount(ctx context.Context, req *sapb.RegistrationID, _ ...grpc.CallOption) (*sapb.Count, error) {
	blog.Info(ctx, "Unpause account", blog.Acct(req.Id))
	return &sapb.Count{Count: 1}, nil
}
