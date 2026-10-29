package cabf_cs_br

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/*
7.1.4.2.3 Subject distinguished name field - Non-EV Code Signing Certificates
c. Certificate Field: subject:localityName (OID: 2.5.4.7)
Required/Optional: Required if the subject:stateOrProvinceName field is absent. Optional if the subject:stateOrProvinceName field is present.
Contents: If present, the subject:localityName field MUST contain the Subject’s locality information as verified under BR Section 3.2.
If the subject:countryName field specifies the ISO 3166-1 user-assigned code of XX in accordance with BR Section 7.1.4.2.2.h., the
subject:localityName field MAY contain the Subject’s locality and/or state or province information as verified under BR Section 3.2.2.1 or 3.2.3.

d. Certificate Field: subject:stateOrProvinceName (OID: 2.5.4.8)
Required/Optional: Required if the subject:localityName field is absent. Optional if the subject:localityName field is present.
Contents: If present, the subject:stateOrProvinceName field MUST contain the Subject’s state or province information as verified
under BR Section 3.2.2.1 or 3.2.3. If the subject:countryName field specifies the ISO 3166-1 user-assigned code of XX in accordance with
BR Section 7.1.4.2.2.h., the subject:stateOrProvinceName field MAY contain the full name of the Subject’s country information as verified
under BR Section 3.2.2.1 or 3.2.3.
*/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cs_subject_locality_or_province_required",
			Description:   "Non-EV Code Signing Certificate: at least one of subject:localityName or subject:stateOrProvinceName must be present.",
			Citation:      "CABF CS BRs 7.1.4.2.3.c, 7.1.4.2.3.d",
			Source:        lint.CABFCSBaselineRequirements,
			EffectiveDate: util.CABF_CS_BRs_1_2_Date,
		},
		Lint: NewCsSubjectLocalityOrProvince,
	})
}

type csSubjectLocalityOrProvince struct{}

func NewCsSubjectLocalityOrProvince() lint.LintInterface {
	return &csSubjectLocalityOrProvince{}
}

func (l *csSubjectLocalityOrProvince) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && !util.IsEVCodeSigning(c.PolicyIdentifiers)
}

func (l *csSubjectLocalityOrProvince) Execute(c *x509.Certificate) *lint.LintResult {
	if len(c.Subject.Locality) == 0 && len(c.Subject.Province) == 0 {
		return &lint.LintResult{Status: lint.Error, Details: "at least one of subject:localityName or subject:stateOrProvinceName must be present."}
	}
	return &lint.LintResult{Status: lint.Pass}
}
