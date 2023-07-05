package rfc

import (
	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/zmap/zlint/v3/lint"
)

// noEmptyRevokedCertificatesList checks RFC 5280, Section 5.1.2.6:
// When there are no revoked certificates, the revoked certificates list MUST be
// absent.
func noEmptyRevokedCertificatesList(crl *crl_x509.RevocationList) *lint.LintResult {
	if crl.RevokedCertificates != nil && len(crl.RevokedCertificates) == 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "If the revokedCertificates list is empty, it must not be present",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
