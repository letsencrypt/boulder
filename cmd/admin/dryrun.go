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

type dryRunRAC struct {
	log blog.Logger
}

var _ adminRAClient = (*dryRunRAC)(nil)

func (d dryRunRAC) AdministrativelyRevokeCertificate(ctx context.Context, req *rapb.AdministrativelyRevokeCertificateRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	d.log.Info(ctx, "dry-run: ra.AdministrativelyRevokeCertificate",
		blog.Serial(req.Serial),
		slog.Int64("code", req.Code),
		slog.String("adminName", req.AdminName),
		slog.Bool("skipBlockKey", req.SkipBlockKey),
		slog.Bool("malformed", req.Malformed),
		slog.Int64("crlShard", req.CrlShard),
	)
	return &emptypb.Empty{}, nil
}

type dryRunSAC struct {
	log blog.Logger
}

var _ adminSAClient = (*dryRunSAC)(nil)

func (d dryRunSAC) AddBlockedKey(ctx context.Context, req *sapb.AddBlockedKeyRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	d.log.Info(ctx, "dry-run: sa.AddBlockedKey",
		slog.String("keyHash", hex.EncodeToString(req.KeyHash)),
		slog.Time("added", req.Added.AsTime()),
		slog.String("source", req.Source),
		slog.String("comment", req.Comment),
		slog.Int64("revokedBy", req.RevokedBy),
	)
	return &emptypb.Empty{}, nil
}

func (d dryRunSAC) AddRateLimitOverride(ctx context.Context, req *sapb.AddRateLimitOverrideRequest, _ ...grpc.CallOption) (*sapb.AddRateLimitOverrideResponse, error) {
	d.log.Info(ctx, "dry-run: sa.AddRateLimitOverride",
		slog.Int64("limit", req.Override.LimitEnum),
		slog.String("bucketKey", req.Override.BucketKey),
		slog.String("comment", req.Override.Comment),
		slog.Duration("period", req.Override.Period.AsDuration()),
		slog.Int64("count", req.Override.Count),
		slog.Int64("burst", req.Override.Burst),
		slog.Bool("force", req.Force),
	)
	return &sapb.AddRateLimitOverrideResponse{Inserted: true, Enabled: true}, nil
}

func (d dryRunSAC) DisableRateLimitOverride(ctx context.Context, req *sapb.DisableRateLimitOverrideRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	d.log.Info(ctx, "dry-run: sa.DisableRateLimitOverride",
		slog.Int64("limit", req.LimitEnum),
		slog.String("bucketKey", req.BucketKey),
	)
	return &emptypb.Empty{}, nil
}

func (d dryRunSAC) EnableRateLimitOverride(ctx context.Context, req *sapb.EnableRateLimitOverrideRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	d.log.Info(ctx, "dry-run: sa.EnableRateLimitOverride",
		slog.Int64("limit", req.LimitEnum),
		slog.String("bucketKey", req.BucketKey),
	)
	return &emptypb.Empty{}, nil
}

func (d dryRunSAC) PauseIdentifiers(ctx context.Context, req *sapb.PauseRequest, _ ...grpc.CallOption) (*sapb.PauseIdentifiersResponse, error) {
	d.log.Info(ctx, "dry-run: sa.PauseIdentifiers",
		blog.Acct(req.RegistrationID),
		blog.Idents(identifier.FromProtoSlice(req.Identifiers)...),
	)
	return &sapb.PauseIdentifiersResponse{Paused: int64(len(req.Identifiers))}, nil
}

func (d dryRunSAC) UnpauseAccount(ctx context.Context, req *sapb.RegistrationID, _ ...grpc.CallOption) (*sapb.Count, error) {
	d.log.Info(ctx, "dry-run: sa.UnpauseAccount",
		blog.Acct(req.Id),
	)
	return &sapb.Count{Count: 1}, nil
}

type dryRunSAAdmin struct {
	log blog.Logger
}

var _ saAdminClient = (*dryRunSAAdmin)(nil)

func (d dryRunSAAdmin) CreateIncident(ctx context.Context, req *sapb.CreateIncidentRequest, _ ...grpc.CallOption) (*sapb.Incident, error) {
	d.log.Info(ctx, "dry-run: saa.CreateIncident",
		slog.String("incident", req.SerialTable),
		slog.String("url", req.Url),
		slog.Time("renewBy", req.RenewBy.AsTime()),
	)
	return &sapb.Incident{SerialTable: req.SerialTable, Url: req.Url, RenewBy: req.RenewBy, Enabled: false}, nil
}

func (d dryRunSAAdmin) UpdateIncident(ctx context.Context, req *sapb.UpdateIncidentRequest, _ ...grpc.CallOption) (*sapb.Incident, error) {
	d.log.Info(ctx, "dry-run: saa.UpdateIncident",
		slog.String("incident", req.SerialTable),
		slog.String("url", req.Url),
		slog.Time("renewBy", req.RenewBy.AsTime()),
		slog.Bool("enabled", req.GetEnabled()),
	)

	out := &sapb.Incident{SerialTable: req.SerialTable, Url: req.Url, RenewBy: req.RenewBy}
	if req.Enabled != nil {
		out.Enabled = *req.Enabled
	}
	return out, nil
}

func (d dryRunSAAdmin) AddSerialsToIncident(ctx context.Context, _ ...grpc.CallOption) (grpc.ClientStreamingClient[sapb.AddSerialsToIncidentRequest, emptypb.Empty], error) {
	return &dryRunAddSerialsStream{ctx: ctx, log: d.log}, nil
}

type dryRunAddSerialsStream struct {
	grpc.ClientStream
	ctx      context.Context
	log      blog.Logger
	incident string
	count    int
}

func (d *dryRunAddSerialsStream) Send(req *sapb.AddSerialsToIncidentRequest) error {
	switch payload := req.Payload.(type) {
	case *sapb.AddSerialsToIncidentRequest_Metadata:
		d.incident = payload.Metadata.SerialTable
	case *sapb.AddSerialsToIncidentRequest_Batch:
		d.count += len(payload.Batch.Serials)
	}
	return nil
}

func (d *dryRunAddSerialsStream) CloseAndRecv() (*emptypb.Empty, error) {
	d.log.Info(d.ctx, "dry-run: saa.AddSerialsToIncident",
		slog.String("incident", d.incident),
		slog.Int("count", d.count),
	)
	return &emptypb.Empty{}, nil
}
