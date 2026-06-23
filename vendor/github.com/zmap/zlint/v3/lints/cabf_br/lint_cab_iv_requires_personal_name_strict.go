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

type CertPolicyRequiresPersonalNameStrict struct{}

/************************************************
--- Citation History of this Requirement ---
v2.0.0 to v2.2.5: 7.1.2.7.3

--- Version Notes ---
This requirement was baselined at v2.2.5 and is current.

--- Requirements Language ---
TLS BRs: 7.1.2.7.3 Individual Validated
Certificate Policy Identifier: 2.23.140.1.2.3

The following table details the acceptable AttributeTypes that may appear within the
type field of an AttributeTypeAndValue, as well as the contents permitted within the
value field.

+----------------+----------+---------------------------+---------------+
| Attribute Name | Presence | Value                     | Verification  |
+----------------+----------+---------------------------+---------------+
| surname        | MUST     | The Subject’s surname.    | Section 3.2.3 |
+----------------+----------+---------------------------+---------------+
| givenName      | MUST     | The Subject’s given name. | Section 3.2.3 |
+----------------+----------+---------------------------+---------------+

************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cab_iv_requires_personal_name_strict",
			Description:   "If certificate policy 2.23.140.1.2.3 is included givenName and surname MUST be included in subject",
			Citation:      "BRs: 7.1.2.7.3",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_2_0_0_Date,
		},
		Lint: NewCertPolicyRequiresPersonalNameStrict,
	})
}

func NewCertPolicyRequiresPersonalNameStrict() lint.LintInterface {
	return &CertPolicyRequiresPersonalNameStrict{}
}

func (l *CertPolicyRequiresPersonalNameStrict) CheckApplies(cert *x509.Certificate) bool {
	return util.SliceContainsOID(cert.PolicyIdentifiers, util.BRIndividualValidatedOID) && !util.IsCACert(cert)
}

func (l *CertPolicyRequiresPersonalNameStrict) Execute(cert *x509.Certificate) *lint.LintResult {
	var out lint.LintResult
	if util.TypeInName(&cert.Subject, util.GivenNameOID) && util.TypeInName(&cert.Subject, util.SurnameOID) {
		out.Status = lint.Pass
	} else {
		out.Status = lint.Error
		out.Details = "Subject MUST include both givenName and surname for Individual Validation (2.23.140.1.2.3) certificates"
	}
	return &out
}
