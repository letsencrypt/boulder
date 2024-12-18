package cabf_cs_br

import (
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/*7.1.2.3 b. cRLDistributionPoints
This extension MUST be present. It MUST NOT be marked critical, and it MUST contain the
HTTP URL of the CA’s CRL service*/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cs_crl_distribution_points",
			Description:   "This extension MUST be present. It MUST NOT be marked critical. It MUST contain the HTTP URL of the CA's CRL service",
			Citation:      "CABF CS BRs 7.1.2.3.b",
			Source:        lint.CABFCSBaselineRequirements,
			EffectiveDate: util.CABF_CS_BRs_1_2_Date,
		},
		Lint: NewCrlDistributionPoints,
	})
}

type crlDistributionPoints struct{}

func NewCrlDistributionPoints() lint.LintInterface {
	return &crlDistributionPoints{}
}

func (l *crlDistributionPoints) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) || util.IsSubCA(c)
}

func (l *crlDistributionPoints) Execute(c *x509.Certificate) *lint.LintResult {
	cdp := util.GetExtFromCert(c, util.CrlDistOID)
	if cdp == nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "The cRLDistributionPoints extension MUST be present."}
	}

	if cdp.Critical {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "The cRLDistributionPoints MUST NOT be marked critical."}
	}

	// MUST contain the HTTP URL of the CA’s CRL service
	for _, uri := range c.CRLDistributionPoints {
		if !strings.HasPrefix(uri, "http://") {
			return &lint.LintResult{Status: lint.Error, Details: "cRLDistributionPoints MUST contain the HTTP URL of the CA's CRL service"}
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
