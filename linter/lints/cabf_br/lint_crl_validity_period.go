package cabfbr

import (
	"time"

	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/zmap/zlint/v3/lint"
)

// hasAcceptableValidity checks Baseline Requirements, Section 4.9.7:
// The value of the nextUpdate field MUST NOT be more than ten days beyond the
// value of the thisUpdate field.
func hasAcceptableValidity(crl *crl_x509.RevocationList) *lint.LintResult {
	validity := crl.NextUpdate.Sub(crl.ThisUpdate)
	if validity <= 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRL has NextUpdate at or before ThisUpdate",
		}
	} else if validity > 10*24*time.Hour {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRL has validity period greater than ten days",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
