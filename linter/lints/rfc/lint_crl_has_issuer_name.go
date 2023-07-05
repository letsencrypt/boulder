package rfc

import (
	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/zmap/zlint/v3/lint"
)

// hasIssuerName checks RFC 5280, Section 5.1.2.3:
// The issuer field MUST contain a non-empty X.500 distinguished name (DN).
// This lint does not enforce that the issuer field complies with the rest of
// the encoding rules of a certificate issuer name, because it (perhaps wrongly)
// assumes that those were checked when the issuer was itself issued, and on all
// certificates issued by this CRL issuer. Also because there are just a lot of
// things to check there, and zlint doesn't expose a public helper for it.
func hasIssuerName(crl *crl_x509.RevocationList) *lint.LintResult {
	if len(crl.Issuer.Names) == 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRLs MUST have a non-empty issuer field",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
