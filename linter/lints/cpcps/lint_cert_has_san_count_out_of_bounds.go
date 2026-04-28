package cpcps

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"github.com/letsencrypt/boulder/linter/lints"
)

type certSubjectAltNamesCountOutOfBounds struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cert_has_san_count_out_of_bounds",
			Description:   "Let's Encrypt Subscriber Certificaes must have a count of subjectAlternateNames within specific bounds defined by our CPS",
			Citation:      "CPS: 7.1",
			Source:        lints.LetsEncryptCPS,
			EffectiveDate: lints.CPSV33Date, // TODO: probably earlier?
		},
		Lint: CertNamesCountOutOfBounds,
	})
}

func CertNamesCountOutOfBounds() lint.CertificateLintInterface {
	return &certSubjectAltNamesCountOutOfBounds{}
}

func (l *certSubjectAltNamesCountOutOfBounds) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.SubjectAlternateNameOID) && (len(c.DNSNames) > 0 || len(c.IPAddresses) > 0)
}

func (l *certSubjectAltNamesCountOutOfBounds) Execute(c *x509.Certificate) *lint.LintResult {
	/*
	 * CP/CPS 7.1: "A sequence of 1 to 100 dNSNames or ipAddresses (critical if no CN)"
	 *
	 * more likely to encounter certs with greater than 100 than with fewer than 1
	 * so testing that failure first
	 */
	totalSANs := len(c.DNSNames) + len(c.IPAddresses)

	if totalSANs > 100 || totalSANs < 1 {
		return &lint.LintResult{Status: lint.Error}
	}

	return &lint.LintResult{Status: lint.Pass}
}
