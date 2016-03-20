package mocks

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/letsencrypt/boulder/core"
)

// MockCA is a mock of a CA that always returns the cert from PEM in response to
// IssueCertificate.
type MockCA struct {
	PEM []byte
}

// IssueCertificate is a mock
func (ca *MockCA) IssueCertificate(csr x509.CertificateRequest, regID int64) (core.Certificate, error) {
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

// GenerateOCSP is a mock
func (ca *MockCA) GenerateOCSP(xferObj core.OCSPSigningRequest) (ocsp []byte, err error) {
	return
}

// RevokeCertificate is a mock
func (ca *MockCA) RevokeCertificate(serial string, reasonCode core.RevocationCode) (err error) {
	return
}
