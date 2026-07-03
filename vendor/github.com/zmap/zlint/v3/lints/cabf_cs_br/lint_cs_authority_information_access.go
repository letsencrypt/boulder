package cabf_cs_br

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/*7.1.2.3 a. authorityInformationAccess
This extension MUST be present. It MUST NOT be marked critical.*/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cs_authority_information_access",
			Description:   "The authorityInformationAccess extension MUST be present and MUST NOT be marked critical.",
			Citation:      "CABF CS BRs 7.1.2.3.a",
			Source:        lint.CABFCSBaselineRequirements,
			EffectiveDate: util.CABF_CS_BRs_1_2_Date,
		},
		Lint: NewCsAuthorityInformationAccess,
	})
}

type csAuthorityInformationAccess struct{}

func NewCsAuthorityInformationAccess() lint.LintInterface {
	return &csAuthorityInformationAccess{}
}

func (l *csAuthorityInformationAccess) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) || util.IsSubCA(c)
}

func (l *csAuthorityInformationAccess) Execute(c *x509.Certificate) *lint.LintResult {
	aia := util.GetExtFromCert(c, util.AiaOID)
	if aia == nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "authorityInformationAccess extension MUST be present."}
	}

	if aia.Critical {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "authorityInformationAccess extension MUST NOT be marked critical."}
	}

	return &lint.LintResult{Status: lint.Pass}
}
