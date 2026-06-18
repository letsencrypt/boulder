package cabf_br

/*
 * ZLint Copyright 2024 Regents of the University of Michigan
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

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type CertPolicyRequiresPersonalName struct{}

/************************************************
--- Citation History of this Requirement ---
v1.3.1 to v1.7.2: 7.1.6.1
v1.7.3 to v1.8.7: 7.1.6.4

--- Version Notes ---
This requirement was rewritten in v2.0.0 and this lint was replaced by e_cab_iv_requires_personal_name_strict.
The language below represents the last version of the requirement implemented by this lint as it appeared in v1.8.7.

--- Requirements Language ---
BRs: 7.1.6.4
Certificate Policy Identifier: 2.23.140.1.2.3
If the Certificate complies with these Requirements and includes Subject Identity Information
that is verified in accordance with Section 3.2.3.
Such Certificates MUST also include either organizationName or both givenName and
surname, localityName (to the extent such field is required under Section 7.1.4.2.2),
stateOrProvinceName (to the extent required under Section 7.1.4.2.2), and countryName in
the Subject field.
************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:            "e_cab_iv_requires_personal_name",
			Description:     "If certificate policy 2.23.140.1.2.3 is included, either organizationName or givenName and surname MUST be included in subject",
			Citation:        "BRs: 7.1.6.4",
			Source:          lint.CABFBaselineRequirements,
			EffectiveDate:   util.CABV131Date,
			IneffectiveDate: util.CABFBRs_2_0_0_Date,
		},
		Lint: NewCertPolicyRequiresPersonalName,
	})
}

func NewCertPolicyRequiresPersonalName() lint.LintInterface {
	return &CertPolicyRequiresPersonalName{}
}

func (l *CertPolicyRequiresPersonalName) CheckApplies(cert *x509.Certificate) bool {
	return util.SliceContainsOID(cert.PolicyIdentifiers, util.BRIndividualValidatedOID) && !util.IsCACert(cert)
}

func (l *CertPolicyRequiresPersonalName) Execute(cert *x509.Certificate) *lint.LintResult {
	var out lint.LintResult
	if util.TypeInName(&cert.Subject, util.OrganizationNameOID) || (util.TypeInName(&cert.Subject, util.GivenNameOID) && util.TypeInName(&cert.Subject, util.SurnameOID)) {
		out.Status = lint.Pass
	} else {
		out.Status = lint.Error
	}
	return &out
}
