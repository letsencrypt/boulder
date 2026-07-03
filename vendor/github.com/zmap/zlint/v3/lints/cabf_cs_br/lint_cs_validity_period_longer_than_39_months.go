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
			Name:            "e_cs_max_validity_period_39_months",
			Description:     "Code Signing certificate validity must not exceed 39 months for certificates issued before March 1st, 2026",
			Citation:        "CS BR 6.3.2 - v3.10",
			Source:          lint.CABFCSBaselineRequirements,
			EffectiveDate:   util.CABF_CS_BRs_1_2_Date, // Effective from v1.2, the quote is from v3.10
			IneffectiveDate: util.CABF_CS_CSC_31_Date,
		},
		Lint: NewCsMaxValidityPeriodLongerThan39Months,
	})
}

type csMaxValidityPeriodLongerThan39Months struct{}

func NewCsMaxValidityPeriodLongerThan39Months() lint.CertificateLintInterface {
	return &csMaxValidityPeriodLongerThan39Months{}
}

func (l *csMaxValidityPeriodLongerThan39Months) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *csMaxValidityPeriodLongerThan39Months) Execute(c *x509.Certificate) *lint.LintResult {
	// difference between notBefore and notAfter MUST not be longer than 39 months
	maxValidity := c.NotBefore.AddDate(0, 39, 0)

	if c.NotAfter.After(maxValidity) {
		return &lint.LintResult{Status: lint.Error, Details: "Code Signing certificates must have a validity period of 39 months or less"}
	}

	return &lint.LintResult{Status: lint.Pass}
}
