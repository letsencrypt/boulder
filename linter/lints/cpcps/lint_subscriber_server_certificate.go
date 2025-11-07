package cpcps

import (
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"github.com/letsencrypt/boulder/linter/lints"
)

type subscriberServerCertificateMatchesCPSProfile struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_subscriber_server_certificate_matches_cps_profile",
			Description:   "Let's Encrypt Subscriber Server Certificates are issued in accordance with the CP/CPS Profile",
			Citation:      "CPS: 7.1",
			Source:        lints.LetsEncryptCPS,
			EffectiveDate: lints.GenYHierarchyDate,
		},
		Lint: NewSubscriberServerCertificateMatchesCPSProfile,
	})
}

func NewSubscriberServerCertificateMatchesCPSProfile() lint.CertificateLintInterface {
	return &subscriberServerCertificateMatchesCPSProfile{}
}

func (l *subscriberServerCertificateMatchesCPSProfile) CheckApplies(c *x509.Certificate) bool {
	return util.IsServerAuthCert(c) && !c.IsCA
}

func (l *subscriberServerCertificateMatchesCPSProfile) Execute(c *x509.Certificate) *lint.LintResult {
	// CPS 7.1: "DV SSL End Entity Certificate Validity Period: Up to 100 days."
	maxValidity := 100 * lints.BRDay

	// RFC 5280 4.1.2.5: "The validity period for a certificate is the period
	// of time from notBefore through notAfter, inclusive."
	certValidity := c.NotAfter.Add(time.Second).Sub(c.NotBefore)

	if certValidity > maxValidity {
		return &lint.LintResult{Status: lint.Error}
	}

	return &lint.LintResult{Status: lint.Pass}
}
