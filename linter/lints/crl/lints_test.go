package crl

import (
	"encoding/pem"
	"os"
	"testing"

	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/letsencrypt/boulder/test"
	"github.com/zmap/zlint/v3/lint"
)

func loadPEMCRL(t *testing.T, filename string) *crl_x509.RevocationList {
	t.Helper()
	file, err := os.ReadFile(filename)
	test.AssertNotError(t, err, "reading CRL file")
	block, rest := pem.Decode(file)
	test.AssertEquals(t, block.Type, "X509 CRL")
	test.AssertEquals(t, len(rest), 0)
	crl, err := crl_x509.ParseRevocationList(block.Bytes)
	test.AssertNotError(t, err, "parsing CRL bytes")
	return crl
}

func TestHasIssuerName(t *testing.T) {
	crl := loadPEMCRL(t, "testdata/no_issuer_name.pem")
	res := hasIssuerName(crl)
	test.AssertEquals(t, res.Status, lint.Error)
}
