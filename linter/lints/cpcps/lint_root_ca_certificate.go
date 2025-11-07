package cpcps

import (
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"github.com/letsencrypt/boulder/linter/lints"
)

type rootCACertificateMatchesCPSProfile struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_root_ca_certificate_matches_cps_profile",
			Description:   "Let's Encrypt Root CA Certificates are issued in accordance with the CP/CPS Profile",
			Citation:      "CPS: 7.1",
			Source:        lints.LetsEncryptCPS,
			EffectiveDate: lints.GenYHierarchyDate,
		},
		Lint: NewRootCACertificateMatchesCPSProfile,
	})
}

func NewRootCACertificateMatchesCPSProfile() lint.CertificateLintInterface {
	return &rootCACertificateMatchesCPSProfile{}
}

func (l *rootCACertificateMatchesCPSProfile) CheckApplies(c *x509.Certificate) bool {
	return util.IsRootCA(c)
}

func (l *rootCACertificateMatchesCPSProfile) Execute(c *x509.Certificate) *lint.LintResult {
	// CPS 7.1: "Root CA Certificate Validity Period: Up to 25 years."
	maxValidity := 25 * 365 * lints.BRDay

	// RFC 5280 4.1.2.5: "The validity period for a certificate is the period
	// of time from notBefore through notAfter, inclusive."
	certValidity := c.NotAfter.Add(time.Second).Sub(c.NotBefore)

	if certValidity > maxValidity {
		return &lint.LintResult{Status: lint.Error}
	}

	return &lint.LintResult{Status: lint.Pass}
}
