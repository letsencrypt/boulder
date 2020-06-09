// Package issuercerts defines types representing a certificate that issue other
// certificates.
package issuercerts

import (
	"crypto/sha256"
	"crypto/x509"
	"math/big"

	"github.com/letsencrypt/boulder/core"
)

type Issuer struct {
	Cert *x509.Certificate
}
type ID int64

// New reads an issuer certificate from a file and returns an Issuer.
func FromFile(filename string) (*Issuer, error) {
	cert, err := core.LoadCert(filename)
	if err != nil {
		return nil, err
	}
	return &Issuer{cert}, nil
}

func FromCert(cert *x509.Certificate) *Issuer {
	return &Issuer{cert}
}

// idForIssuer generates a stable ID for an issuer certificate, based on a hash
// of the issuer certificate's bytes. This is used for identifying which issuer
// issued a certificate in the certificateStatus table.
func (issuer *Issuer) ID() ID {
	h := sha256.Sum256(issuer.Cert.Raw)
	return ID(big.NewInt(0).SetBytes(h[:4]).Int64())
}
