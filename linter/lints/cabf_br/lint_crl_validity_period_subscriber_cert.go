package cabfbr

import (
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type crlValidityPeriodSubscriberCert struct{}

/************************************************
Baseline Requirements, Section 4.9.7:
For the status of Subscriber Certificates [...] the value of the nextUpdate
field MUST NOT be more than ten days beyond the value of the thisUpdate field.
************************************************/

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_crl_validity_period_subscriber_cert",
			Description:   "CRLs must have an acceptable validity period",
			Citation:      "BRs: 4.9.7",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_1_2_1_Date,
		},
		Lint: NewCrlValidityPeriodSubscriberCert,
	})
}

func NewCrlValidityPeriodSubscriberCert() lint.RevocationListLintInterface {
	return &crlValidityPeriodSubscriberCert{}
}

func (l *crlValidityPeriodSubscriberCert) CheckApplies(c *x509.RevocationList) bool {
	return true
}

func (l *crlValidityPeriodSubscriberCert) Execute(c *x509.RevocationList) *lint.LintResult {
	validity := c.NextUpdate.Sub(c.ThisUpdate)
	if validity <= 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRL has NextUpdate at or before ThisUpdate",
		}
	}
	if validity > 10*24*time.Hour {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRL has validity period greater than ten days",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
