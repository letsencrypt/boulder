package cpcps

import (
	"encoding/asn1"

	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/zmap/zlint/v3/lint"
)

// isNotDelta checks that the CRL is not a Delta CRL. (RFC 5280, Section 5.2.4).
// There's no requirement against this, but Delta CRLs come with extra
// requirements we don't want to deal with.
func isNotDelta(crl *crl_x509.RevocationList) *lint.LintResult {
	deltaCRLIndicatorOID := asn1.ObjectIdentifier{2, 5, 29, 27} // id-ce-deltaCRLIndicator
	if getExtWithOID(crl.Extensions, deltaCRLIndicatorOID) != nil {
		return &lint.LintResult{
			Status:  lint.Notice,
			Details: "CRL is a Delta CRL",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
