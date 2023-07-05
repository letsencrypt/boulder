package cpcps

import (
	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zlint/v3/lint"
)

// hasNoAIA checks that the CRL is does not have an Authority Information Access
// extension (RFC 5280, Section 5.2.7). There's no requirement against this, but
// AIAs come with extra requirements we don't want to deal with.
func hasNoAIA(crl *crl_x509.RevocationList) *lint.LintResult {
	aiaOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1} // id-pe-authorityInfoAccess
	if getExtWithOID(crl.Extensions, aiaOID) != nil {
		return &lint.LintResult{
			Status:  lint.Notice,
			Details: "CRL has an Authority Information Access url",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
