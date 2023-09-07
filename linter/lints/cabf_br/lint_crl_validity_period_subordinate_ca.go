package cabfbr

import (
	"github.com/letsencrypt/boulder/linter/lints"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type crlValidityPeriodSubordinateCA struct{}

/************************************************
Baseline Requirements, Section 4.9.7:
For the status of Subordinate CA Certificates [...]. The value of the nextUpdate
field MUST NOT be more than twelve months beyond the value of the thisUpdate
field.
************************************************/

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_crl_validity_period_subordinate_ca",
			Description:   "CRLs must have an acceptable validity period",
			Citation:      "BRs: 4.9.7",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_1_2_1_Date,
		},
		Lint: NewCrlValidityPeriodSubordinateCA,
	})
}

func NewCrlValidityPeriodSubordinateCA() lint.RevocationListLintInterface {
	return &crlValidityPeriodSubordinateCA{}
}

func (l *crlValidityPeriodSubordinateCA) CheckApplies(c *x509.RevocationList) bool {
	return true
}

func (l *crlValidityPeriodSubordinateCA) Execute(c *x509.RevocationList) *lint.LintResult {
	validity := c.NextUpdate.Sub(c.ThisUpdate)
	if validity <= 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRL has NextUpdate at or before ThisUpdate",
		}
	}
	if validity > 365*lints.BRDay {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRL has validity period greater than 12 months (365 days)",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
