package cabf_cs_br

import (
	"github.com/zmap/zcrypto/x509"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/*
6.3.2 Certificate operational periods and key pair usage periods
For Code Signing Certificates issued before March 1st, 2026, the validity period MUST NOT exceed
39 months. For Code Signing Certificates issued on or after March 1st, 2026, the validity period
MUST NOT exceed 460 days.
*/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cs_max_validity_period_460_days",
			Description:   "Code Signing certificate validity must not exceed 460 days for certificates issued on or after March 1st, 2026",
			Citation:      "CS BR 6.3.2 - v3.10",
			Source:        lint.CABFCSBaselineRequirements,
			EffectiveDate: util.CABF_CS_CSC_31_Date,
		},
		Lint: NewCsMaxValidityPeriodLongerThan460Days,
	})
}

type csMaxValidityPeriodLongerThan460Days struct{}

func NewCsMaxValidityPeriodLongerThan460Days() lint.CertificateLintInterface {
	return &csMaxValidityPeriodLongerThan460Days{}
}

func (l *csMaxValidityPeriodLongerThan460Days) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *csMaxValidityPeriodLongerThan460Days) Execute(c *x509.Certificate) *lint.LintResult {
	// difference between notBefore and notAfter MUST not be longer than 460 days
	maxValidity := c.NotBefore.AddDate(0, 0, 460)

	if c.NotAfter.After(maxValidity) {
		return &lint.LintResult{Status: lint.Error, Details: "Code Signing certificates must have a validity period of 460 days or less"}
	}

	return &lint.LintResult{Status: lint.Pass}
}
