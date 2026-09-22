package main

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/types/known/emptypb"

	blog "github.com/letsencrypt/boulder/log"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type dryRunRAC struct {
	log blog.Logger
}

var _ adminRAClient = (*dryRunRAC)(nil)

func (d dryRunRAC) AdministrativelyRevokeCertificate(_ context.Context, req *rapb.AdministrativelyRevokeCertificateRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	b, err := prototext.Marshal(req)
	if err != nil {
		return nil, err
	}
	d.log.Infof("dry-run: %#v", string(b))
	return &emptypb.Empty{}, nil
}

type dryRunSAC struct {
	log blog.Logger
}

var _ adminSAClient = (*dryRunSAC)(nil)

func (d dryRunSAC) AddBlockedKey(_ context.Context, req *sapb.AddBlockedKeyRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	d.log.Infof("dry-run: Block SPKI hash %x by %s %s", req.KeyHash, req.Comment, req.Source)
	return &emptypb.Empty{}, nil
}

func (d dryRunSAC) AddRateLimitOverride(_ context.Context, req *sapb.AddRateLimitOverrideRequest, _ ...grpc.CallOption) (*sapb.AddRateLimitOverrideResponse, error) {
	d.log.Infof("dry-run: Add override for %q (%s)", req.Override.BucketKey, req.Override.Comment)
	return &sapb.AddRateLimitOverrideResponse{Inserted: true, Enabled: true}, nil
}

func (d dryRunSAC) DisableRateLimitOverride(_ context.Context, req *sapb.DisableRateLimitOverrideRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	d.log.Infof("dry-run: Disable override for %q", req.BucketKey)
	return &emptypb.Empty{}, nil
}

func (d dryRunSAC) EnableRateLimitOverride(_ context.Context, req *sapb.EnableRateLimitOverrideRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	d.log.Infof("dry-run: Enable override for %q", req.BucketKey)
	return &emptypb.Empty{}, nil
}

func (d dryRunSAC) PauseIdentifiers(_ context.Context, req *sapb.PauseRequest, _ ...grpc.CallOption) (*sapb.PauseIdentifiersResponse, error) {
	d.log.Infof("dry-run: Pause identifiers %#v for account %d", req.Identifiers, req.RegistrationID)
	return &sapb.PauseIdentifiersResponse{Paused: int64(len(req.Identifiers))}, nil
}

func (d dryRunSAC) UnpauseAccount(_ context.Context, req *sapb.RegistrationID, _ ...grpc.CallOption) (*sapb.Count, error) {
	d.log.Infof("dry-run: Unpause account %d", req.Id)
	return &sapb.Count{Count: 1}, nil
}

type dryRunSAAdmin struct {
	log blog.Logger
}

var _ saAdminClient = (*dryRunSAAdmin)(nil)

func (d dryRunSAAdmin) CreateIncident(_ context.Context, req *sapb.CreateIncidentRequest, _ ...grpc.CallOption) (*sapb.Incident, error) {
	d.log.Infof("dry-run: Create incident %q (url=%q, renewBy=%s)", req.SerialTable, req.Url, req.RenewBy.AsTime())
	return &sapb.Incident{SerialTable: req.SerialTable, Url: req.Url, RenewBy: req.RenewBy, Enabled: false}, nil
}

func (d dryRunSAAdmin) UpdateIncident(_ context.Context, req *sapb.UpdateIncidentRequest, _ ...grpc.CallOption) (*sapb.Incident, error) {
	d.log.Infof("dry-run: Update incident %q url=%q renewBy=%v enabled=%v", req.SerialTable, req.Url, req.RenewBy, req.GetEnabled())
	out := &sapb.Incident{SerialTable: req.SerialTable, Url: req.Url, RenewBy: req.RenewBy}
	if req.Enabled != nil {
		out.Enabled = *req.Enabled
	}
	return out, nil
}

func (d dryRunSAAdmin) AddSerialsToIncident(_ context.Context, _ ...grpc.CallOption) (grpc.ClientStreamingClient[sapb.AddSerialsToIncidentRequest, emptypb.Empty], error) {
	return &dryRunAddSerialsStream{log: d.log}, nil
}

type dryRunAddSerialsStream struct {
	grpc.ClientStream
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
	d.log.Infof("dry-run: Add %d serials to incident %q", d.count, d.incident)
	return &emptypb.Empty{}, nil
}
