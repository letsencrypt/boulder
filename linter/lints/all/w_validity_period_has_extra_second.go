package subscriber

import (
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"

	"github.com/letsencrypt/boulder/linter/lints"
)

type anyCertValidityNotRound struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "w_validity_period_has_extra_second",
		Description:   "Let's Encrypt Certificates have Validity Periods that are a round number of seconds",
		Citation:      "CPS: 7.1",
		Source:        lints.LetsEncryptCPSAll,
		EffectiveDate: lints.CPSV33Date,
		Lint:          &anyCertValidityNotRound{},
	})
}

func (l *anyCertValidityNotRound) Initialize() error {
	return nil
}

func (l *anyCertValidityNotRound) CheckApplies(c *x509.Certificate) bool {
	return true
}

func (l *anyCertValidityNotRound) Execute(c *x509.Certificate) *lint.LintResult {
	// RFC 5280 4.1.2.5: "The validity period for a certificate is the period
	// of time from notBefore through notAfter, inclusive."
	certValidity := c.NotAfter.Add(time.Second).Sub(c.NotBefore)

	if certValidity%60 == 0 {
		return &lint.LintResult{Status: lint.Pass}
	}

	return &lint.LintResult{Status: lint.Error}
}
