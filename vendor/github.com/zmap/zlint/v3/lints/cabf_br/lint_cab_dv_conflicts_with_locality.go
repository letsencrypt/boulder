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

/*
--- Citation History of this Requirement ---
§9.3.1     v1.0   to v1.2.5
§7.1.6.1   v1.3.0 to v1.7.2
§7.1.6.4   v1.7.3 to v1.8.7
Superseded in v2.0.0 by a new general prohibition on extra name types not specifically allowed.

--- Version Notes ---
This practice is still prohibited, but the requirements moved from specifically prohibiting certain
name types to blocking everything but commonName and countryName in v2.0.0. (See e_cab_dv_subject_invalid_values)

This requirement was removed in v2.0.0 and is historical. The language below is from v1.8.7,
the last relevant version.

--- Requirements Language ---
BRs: 7.1.6.4
Certificate Policy Identifier: 2.23.140.1.2.1
If the Certificate complies with these requirements and lacks Subject identity information that
has been verified in accordance with Section 3.2.2.1 or Section 3.2.3.
Such Certificates MUST NOT include organizationName, givenName, surname,
streetAddress, localityName, stateOrProvinceName, or postalCode in the Subject field.
*/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:            "e_cab_dv_conflicts_with_locality",
			Description:     "If certificate policy 2.23.140.1.2.1 (CA/B BR domain validated) is included, locality name MUST NOT be included in subject",
			Citation:        "BRs: 7.1.6.4",
			Source:          lint.CABFBaselineRequirements,
			EffectiveDate:   util.CABEffectiveDate,
			IneffectiveDate: util.CABFBRs_2_0_0_Date,
		},
		Lint: NewCertPolicyConflictsWithLocality,
	})
}

func NewCertPolicyConflictsWithLocality() lint.LintInterface {
	return &certPolicyConflictsWithLocality{}
}

type certPolicyConflictsWithLocality struct{}

func (l *certPolicyConflictsWithLocality) CheckApplies(cert *x509.Certificate) bool {
	return util.SliceContainsOID(cert.PolicyIdentifiers, util.BRDomainValidatedOID) && !util.IsCACert(cert)
}

func (l *certPolicyConflictsWithLocality) Execute(cert *x509.Certificate) *lint.LintResult {
	if util.TypeInName(&cert.Subject, util.LocalityNameOID) {
		return &lint.LintResult{Status: lint.Error}
	}
	return &lint.LintResult{Status: lint.Pass}
}
