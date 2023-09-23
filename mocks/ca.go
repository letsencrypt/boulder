package mocks

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	capb "github.com/letsencrypt/boulder/ca/proto"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// MockCA is a mock of a CA that always returns the cert from PEM in response to
// IssueCertificate.
type MockCA struct {
	PEM []byte
}

// IssuePrecertificate is a mock
func (ca *MockCA) IssuePrecertificate(ctx context.Context, _ *capb.IssueCertificateRequest, _ ...grpc.CallOption) (*capb.IssuePrecertificateResponse, error) {
	if ca.PEM == nil {
		return nil, fmt.Errorf("MockCA's PEM field must be set before calling IssueCertificate")
	}
	block, _ := pem.Decode(ca.PEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &capb.IssuePrecertificateResponse{
		DER: cert.Raw,
	}, nil
}

// IssueCertificateForPrecertificate is a mock
func (ca *MockCA) IssueCertificateForPrecertificate(ctx context.Context, req *capb.IssueCertificateForPrecertificateRequest, _ ...grpc.CallOption) (*corepb.Certificate, error) {
	now := time.Now()
	expires := now.Add(1 * time.Hour)

	return &corepb.Certificate{
		Der:            req.DER,
		RegistrationID: 1,
		Serial:         "mock",
		Digest:         "mock",
		IssuedNS:       now.UnixNano(),
		Issued:         timestamppb.New(now),
		ExpiresNS:      expires.UnixNano(),
		Expires:        timestamppb.New(expires),
	}, nil
}

type MockOCSPGenerator struct{}

// GenerateOCSP is a mock
func (ca *MockOCSPGenerator) GenerateOCSP(ctx context.Context, req *capb.GenerateOCSPRequest, _ ...grpc.CallOption) (*capb.OCSPResponse, error) {
	return nil, nil
}

type MockCRLGenerator struct{}

// GenerateCRL is a mock
func (ca *MockCRLGenerator) GenerateCRL(ctx context.Context, opts ...grpc.CallOption) (capb.CRLGenerator_GenerateCRLClient, error) {
	return nil, nil
}
