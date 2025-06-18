package cabf_cs_br

import (
	"github.com/zmap/zcrypto/x509"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/* 7.1.2.3 Code signing and Timestamp Certificate
e. keyUsage
This extension MUST be present and MUST be marked critical.
The bit position for digitalSignature MUST be set. Bit positions for keyCertSign and
cRLSign MUST NOT be set. All other bit positions SHOULD NOT be set.
*/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cs_key_usage_required",
			Description:   "This extension MUST be present and MUST be marked critical. The bit position for digitalSignature MUST be set. The bit positions for keyCertSign and cRLSign MUST NOT be set. All other bit positions SHOULD NOT be set.",
			Citation:      "CABF CS BRs 7.1.2.3e",
			Source:        lint.CABFCSBaselineRequirements,
			EffectiveDate: util.CABF_CS_BRs_1_2_Date,
		},
		Lint: NewCsKeyUsageRequired,
	})
}

type csKeyUsageRequired struct{}

func NewCsKeyUsageRequired() lint.LintInterface {
	return &csKeyUsageRequired{}
}

func (l *csKeyUsageRequired) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *csKeyUsageRequired) Execute(c *x509.Certificate) *lint.LintResult {
	ku := util.GetExtFromCert(c, util.KeyUsageOID)
	if ku == nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Key usage extension MUST be present.",
		}
	}

	if !ku.Critical {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Key usage extension MUST be marked critical",
		}
	}

	if (c.KeyUsage & x509.KeyUsageDigitalSignature) == 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Code Signing certificate must have digitalSignature key usage",
		}
	}

	// keyCertSign and cRLSign bits MUST NOT be set.
	if (c.KeyUsage & (x509.KeyUsageCertSign | x509.KeyUsageCRLSign)) != 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "keyCertSign and cRLSign key usages MUST NOT be set",
		}
	}

	// All other bit positions SHOULD NOT be set.
	if c.KeyUsage & ^x509.KeyUsageDigitalSignature != 0 {
		return &lint.LintResult{
			Status:  lint.Warn,
			Details: "Only digitalSignature key usage is recommended. Other key usages SHOULD NOT be set."}
	}

	return &lint.LintResult{Status: lint.Pass}
}
