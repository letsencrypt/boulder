package cabf_cs_br

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/*
7.1.4.2.2 Subject distinguished name fields - EV and Non-EV Code Signing Certificates
c. Certificate Field: subject:domainComponent (OID 0.9.2342.19200300.100.1.25)
Required/Optional: Prohibited
Contents: This field MUST not be present in a Code Signing Certificate.
*/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cs_subject_prohibited",
			Description:   "The subject:domainComponent MUST not be present in a Code Signing Certificate.",
			Citation:      "CABF CS BRs 7.1.4.2.3.c",
			Source:        lint.CABFCSBaselineRequirements,
			EffectiveDate: util.CABF_CS_BRs_1_2_Date,
		},
		Lint: NewCsSubjectProhibited,
	})
}

type csSubjectProhibited struct{}

func NewCsSubjectProhibited() lint.LintInterface {
	return &csSubjectProhibited{}
}

func (l *csSubjectProhibited) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *csSubjectProhibited) Execute(c *x509.Certificate) *lint.LintResult {
	if len(c.Subject.DomainComponent) > 0 {
		return &lint.LintResult{Status: lint.Error, Details: "Domain Component MUST not be present in a Code Signing Certificate."}
	}

	return &lint.LintResult{Status: lint.Pass}
}
