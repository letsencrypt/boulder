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

type CertPolicyIVRequiresCountry struct{}

/************************************************
--- Citation History of this Requirement ---
v1.3.1 to v1.7.2: 7.1.6.1
v1.7.3 to v1.8.7: 7.1.6.4
v2.0.0 to v2.2.5: 7.1.2.7.3

--- Version Notes ---
This requirement was baselined at v2.2.5 and is current.

--- Requirements Language ---
TLS BRs: 7.1.2.7.3 Individual Validated

The following table details the acceptable AttributeTypes that may appear within the
type field of an AttributeTypeAndValue, as well as the contents permitted within the
value field.

+----------------+----------+--------------------------------------------------------+---------------+
| Attribute Name | Presence | Value                                                  | Verification  |
+----------------+----------+--------------------------------------------------------+---------------+
| countryName    | MUST     | The two‐letter ISO 3166‐1 country code for the country | Section 3.2.3 |
|                |          | associated with the Subject. If a Country is not       |               |
|                |          | represented by an official ISO 3166‐1 country code,    |               |
|                |          | the CA MUST specify the ISO 3166‐1 user‐assigned code  |               |
|                |          | of XX, indicating that an official ISO 3166‐1 alpha‐2  |               |
|                |          | code has not been assigned.                            |               |
+----------------+----------+--------------------------------------------------------+---------------+
************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cert_policy_iv_requires_country",
			Description:   "If certificate policy 2.23.140.1.2.3 is included, countryName MUST be included in subject",
			Citation:      "BRs: 7.1.2.7.3",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABV131Date,
		},
		Lint: NewCertPolicyIVRequiresCountry,
	})
}

func NewCertPolicyIVRequiresCountry() lint.LintInterface {
	return &CertPolicyIVRequiresCountry{}
}

func (l *CertPolicyIVRequiresCountry) CheckApplies(cert *x509.Certificate) bool {
	return util.SliceContainsOID(cert.PolicyIdentifiers, util.BRIndividualValidatedOID) && !util.IsCACert(cert)
}

func (l *CertPolicyIVRequiresCountry) Execute(cert *x509.Certificate) *lint.LintResult {
	var out lint.LintResult
	if util.TypeInName(&cert.Subject, util.CountryNameOID) {
		out.Status = lint.Pass
	} else {
		out.Status = lint.Error
	}
	return &out
}
