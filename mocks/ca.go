package mocks

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"golang.org/x/net/context"

	caPB "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/revocation"
)

// MockCA is a mock of a CA that always returns the cert from PEM in response to
// IssueCertificate.
type MockCA struct {
	PEM []byte
}

// IssueCertificate is a mock
func (ca *MockCA) IssueCertificate(ctx context.Context, _ *caPB.IssueCertificateRequest) (core.Certificate, error) {
	if ca.PEM == nil {
		return core.Certificate{}, fmt.Errorf("MockCA's PEM field must be set before calling IssueCertificate")
	}
	block, _ := pem.Decode(ca.PEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return core.Certificate{}, err
	}
	return core.Certificate{
		DER: cert.Raw,
	}, nil
}

// IssuePrecertificate is a mock
func (ca *MockCA) IssuePrecertificate(ctx context.Context, _ *caPB.IssueCertificateRequest) (*caPB.IssuePrecertificateResponse, error) {
	if ca.PEM == nil {
		return nil, fmt.Errorf("MockCA's PEM field must be set before calling IssueCertificate")
	}
	block, _ := pem.Decode(ca.PEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &caPB.IssuePrecertificateResponse{
		DER: cert.Raw,
	}, nil
}

// IssueCertificateForPrecertificate is a mock
func (ca *MockCA) IssueCertificateForPrecertificate(ctx context.Context, req *caPB.IssueCertificateForPrecertificateRequest) (core.Certificate, error) {
	return core.Certificate{DER: req.DER}, nil
}

// GenerateOCSP is a mock
func (ca *MockCA) GenerateOCSP(ctx context.Context, xferObj core.OCSPSigningRequest) (ocsp []byte, err error) {
	return
}

// RevokeCertificate is a mock
func (ca *MockCA) RevokeCertificate(ctx context.Context, serial string, reasonCode revocation.Reason) (err error) {
	return
}
