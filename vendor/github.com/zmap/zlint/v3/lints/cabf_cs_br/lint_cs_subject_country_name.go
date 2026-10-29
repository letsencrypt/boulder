package cabf_cs_br

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/*
7.1.4.2.3 Subject distinguished name field - Non-EV Code Signing Certificates
f. Certificate Field: subject:countryName (OID: 2.5.4.6)
Required/Optional: Required
Contents: The subject:countryName MUST contain the two-letter ISO 3166-1 country code associated with the location of
the Subject verified under BR Section 3.2.2.3. If a Country is not represented by an official ISO 3166-1 country code,
the CA MAY specify the ISO 3166-1 user-assigned code of XX indicating that an official ISO 3166-1 alpha-2 code has not
been assigned.
*/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cs_subject_country_name",
			Description:   "The subject:countryName MUST contain the two-letter ISO 3166-1 country code associated with the location of the Subject verified under BR Section 3.2.2.3.",
			Citation:      "CABF CS BRs 7.1.4.2.3.f",
			Source:        lint.CABFCSBaselineRequirements,
			EffectiveDate: util.CABF_CS_BRs_1_2_Date,
		},
		Lint: NewCsSubjectCountryName,
	})
}

type csSubjectCountryName struct{}

func NewCsSubjectCountryName() lint.LintInterface {
	return &csSubjectCountryName{}
}

func (l *csSubjectCountryName) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && !util.IsEVCodeSigning(c.PolicyIdentifiers)
}

func (l *csSubjectCountryName) Execute(c *x509.Certificate) *lint.LintResult {
	if len(c.Subject.Country) == 0 {
		return &lint.LintResult{Status: lint.Error, Details: "No country name found in subject."}
	}

	if !util.IsISOCountryCode(c.Subject.Country[0]) && c.Subject.Country[0] != "XX" {
		return &lint.LintResult{Status: lint.Error, Details: "Country name in subject is not a valid ISO 3166-1 alpha-2 code."}
	}

	return &lint.LintResult{Status: lint.Pass}
}
