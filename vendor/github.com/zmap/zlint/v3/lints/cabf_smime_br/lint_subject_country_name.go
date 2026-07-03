/*
 * ZLint Copyright 2025 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package cabf_smime_br

import (
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/*************************************************************************
7.1.4.2.2 Subject distinguished name fields

n. Certificate Field: subject:countryName (OID: 2.5.4.6)
Contents: If present, the subject:countryName SHALL contain the two-letter ISO 3166-1
country code associated with the location of the Subject verified under Section 3.2.3 for
Organization-validated and Sponsor-validated Certificate Types or Section 3.2.4 for
Individual-validated Certificate Types. If a Country is not represented by an official ISO 3166-1
country code, the CA MAY specify the ISO 3166-1 user-assigned code of XX indicating that an
official ISO 3166-1 alpha-2 code has not been assigned.

See also:
7.1.4.2.3 Subject DN attributes for mailbox-validated profile:
countryName SHALL NOT SHALL NOT SHALL NOT

7.1.4.2.4 Subject DN attributes for organization-validated profile:
countryName MAY //nolint:dupword

7.1.4.2.5 Subject DN attributes for sponsor-validated profile:
countryName MAY //nolint:dupword

7.1.4.2.6 Subject DN attributes for individual-validated profile:
countryName MAY //nolint:dupword
*************************************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_subject_country_name",
			Description:   "If present, the subject:countryName SHALL contain the two‐letter ISO 3166‐1 country code associated with the location of the Subject",
			Citation:      "S/MIME BRs: 7.1.4.2.2n",
			Source:        lint.CABFSMIMEBaselineRequirements,
			EffectiveDate: util.CABF_SMIME_BRs_1_0_0_Date,
		},
		Lint: NewSubjectCountryName,
	})
}

type subjectCountryName struct{}

func NewSubjectCountryName() lint.LintInterface {
	return &subjectCountryName{}
}

func (l *subjectCountryName) CheckApplies(c *x509.Certificate) bool {
	return util.IsOrganizationValidatedCertificate(c) || util.IsSponsorValidatedCertificate(c) || util.IsIndividualValidatedCertificate(c)
}

func (l *subjectCountryName) Execute(c *x509.Certificate) *lint.LintResult {
	for _, cc := range c.Subject.Country {
		if !util.IsISOCountryCode(cc) && strings.ToUpper(cc) != "XX" {
			return &lint.LintResult{Status: lint.Error}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
