package cpcps

import (
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"github.com/letsencrypt/boulder/linter/lints"
)

// globalNamespace aliases zlint's lint.Global so that this lint can
// embed it under an unexported field name.
type globalNamespace = lint.Global //nolint:unused // Used in SharedConfig.

type crossCertificatesNeedEKUs struct {
	globalNamespace //nolint:unused // Used by zlint, not by us.
	// ExistingCertificatePEM should point to the cert being cross-signed. This
	// matches the way our CP/CPS lints are configured. However, for the sake
	// of this lint, the actual contents don't matter: we just use this to
	// determine whether this lint should run (an empty existing cert means
	// that the cert being linted is a new CA, not a cross-sign).
	ExistingCertificatePEM string `toml:"existing_certificate" comment:"The PEM encoding of the existing CA Certificate being cross-signed."`
}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cross_certificates_need_ekus",
			Description:   "When new cross-certificates are issued across PKI hierarchies[...] the following EKU values MUST exist...",
			Citation:      "CCADB: 5.3",
			Source:        lints.CCADBPolicy,
			EffectiveDate: time.Date(2025, time.June, 15, 0, 0, 0, 0, time.UTC),
		},
		Lint: NewCrossCertificatesNeedEKUs,
	})
}

func NewCrossCertificatesNeedEKUs() lint.CertificateLintInterface {
	return &crossCertificatesNeedEKUs{}
}

func (l *crossCertificatesNeedEKUs) Configure() any {
	return l
}

func (l *crossCertificatesNeedEKUs) CheckApplies(c *x509.Certificate) bool {
	// If an existing cert is configured, then we assume this is a cross-sign.
	return util.IsSubCA(c) && len(l.ExistingCertificatePEM) > 0
}

func (l *crossCertificatesNeedEKUs) Execute(c *x509.Certificate) *lint.LintResult {
	// https://github.com/mozilla/www.ccadb.org/blob/a1f11b17315b56c639179e98b0b11dbe69abaa8c/policy.md?plain=1#L371
	// | TLS server authentication | MUST | Only 1.3.6.1.5.5.7.3.1                       |
	// This is actually stricter than CCADB requires, because it makes the
	// assumption that all CA certs issued by LE will be dedicated to single-
	// purpose TLS Server Auth hierarchies.
	if len(c.ExtKeyUsage) != 0 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		return &lint.LintResult{Status: lint.Error, Details: "extKeyUsage does not contain exactly id-kp-serverAuth"}
	}

	return &lint.LintResult{Status: lint.Pass}
}
