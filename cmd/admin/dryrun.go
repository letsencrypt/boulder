package main

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	blog "github.com/letsencrypt/boulder/log"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type dryRunRAC struct {
	rapb.RegistrationAuthorityClient
	log blog.Logger
}

func (d dryRunRAC) AdministrativelyRevokeCertificate(_ context.Context, req *rapb.AdministrativelyRevokeCertificateRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	d.log.Infof("dry-run: %#v", req)
	return &emptypb.Empty{}, nil
}

type dryRunSAC struct {
	sapb.StorageAuthorityClient
	log blog.Logger
}

func (d dryRunSAC) AddBlockedKey(_ context.Context, req *sapb.AddBlockedKeyRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	d.log.Infof("dry-run: %#v", req)
	return &emptypb.Empty{}, nil
}
