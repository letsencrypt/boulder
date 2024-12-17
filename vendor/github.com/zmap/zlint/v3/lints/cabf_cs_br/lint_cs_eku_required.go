package cabf_cs_br

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/* 7.1.2.3 Code signing and Timestamp Certificate
f. extKeyUsage
If the Certificate is a Code Signing Certificate, then id-kp-codeSigning MUST be present
and the following EKUs MAY be present:
	• Lifetime Signing OID (1.3.6.1.4.1.311.10.3.13)
	• id-kp-emailProtection
	• Document Signing (1.3.6.1.4.1.311.3.10.3.12)

If the Certificate is a Timestamp Certificate, then id-kp-timeStamping MUST be present
and MUST be marked critical.
Additionally, the following EKUs MUST NOT be present:
	• anyExtendedKeyUsage
	• id-kp-serverAuth

Other values SHOULD NOT be present. If any other value is present, the CA MUST have a
business agreement with a Platform vendor requiring that EKU in order to issue a
Platform‐specific code signing certificate with that EKU.
*/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cs_eku_required",
			Description:   "If the Certificate is a Code Signing Certificate, then id-kp-codeSigning MUST be present. anyExtendedKeyUsage and id-kp-serverAuth MUST NOT be present.",
			Citation:      "CABF CS BRs 7.1.2.3.f",
			Source:        lint.CABFCSBaselineRequirements,
			EffectiveDate: util.CABF_CS_BRs_1_2_Date,
		},
		Lint: NewCsEKURequired,
	})
}

type csEKURequired struct{}

func NewCsEKURequired() lint.LintInterface {
	return &csEKURequired{}
}

func (l *csEKURequired) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) || util.IsSubCA(c)
}

func (l *csEKURequired) Execute(c *x509.Certificate) *lint.LintResult {
	prohibitedEKUs := map[x509.ExtKeyUsage]struct{}{
		x509.ExtKeyUsageAny:        {},
		x509.ExtKeyUsageServerAuth: {},
	}

	if util.IsSubCA(c) {
		prohibitedEKUs[x509.ExtKeyUsageEmailProtection] = struct{}{}
	}

	hasCodeSigningEKU := false

	for _, eku := range c.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCodeSigning {
			hasCodeSigningEKU = true
		}

		if _, isProhibited := prohibitedEKUs[eku]; isProhibited {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: fmt.Sprintf("Code Signing certificate includes prohibited EKU: %v", eku),
			}
		}
	}

	if !hasCodeSigningEKU {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Code Signing certificate missing required Code Signing EKU",
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
