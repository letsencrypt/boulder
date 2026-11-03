package cabf_br

/*
 * ZLint Copyright 2026 Regents of the University of Michigan
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

type CertPolicyRequiresOrg struct{}

/************************************************
--- Citation History of this Requirement ---
§9.3.1     v1.0   to v1.2.5
§7.1.6.1   v1.3.0 to v1.7.2
§7.1.6.4   v1.7.3 to v1.8.7
§7.1.2.7.4 v2.0.0 to v2.2.7

--- Version Notes ---
Prior to v1.3.1 this profile was known as "Subject Identity Validated" and was renamed to "Organization Validated"
with no requirement changes when the "Individual Validated" profile was split out in that version.

This requirement was baselined at v2.2.7 and is current.

--- Requirements Language ---
TLS BRs: 7.1.2.7.4 Organization Validated

The following table details the acceptable AttributeTypes that may appear within the
type field of an AttributeTypeAndValue, as well as the contents permitted within the
value field.

+------------------+----------+----------------------------------------------------------+-----------------+
| Attribute Name   | Presence | Value                                                    | Verification    |
+------------------+----------+----------------------------------------------------------+-----------------+
| organizationName | MUST     | The Subject’s name and/or DBA/tradename. The CA MAY      | Section 3.2.2.2 |
|                  |          | include information in this field that differs slightly  |                 |
|                  |          | from the verified name, such as common variations or     |                 |
|                  |          | abbreviations, provided that the CA documents the        |                 |
|                  |          | difference and any abbreviations used are locally        |                 |
|                  |          | accepted abbreviations; e.g. if the official record      |                 |
|                  |          | shows “Company Name Incorporated”, the CA MAY use        |                 |
|                  |          | “Company Name Inc.” or “Company Name”. If both are       |                 |
|                  |          | included, the DBA/tradename SHALL appear first, followed |                 |
|                  |          | by the Subject’s name in parentheses.                    |                 |
+------------------+----------+----------------------------------------------------------+-----------------+
************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cab_ov_requires_org",
			Description:   "If certificate policy 2.23.140.1.2.2 is included, organizationName MUST be included in subject",
			Citation:      "BRs: 7.1.2.7.4",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABEffectiveDate,
		},
		Lint: NewCertPolicyRequiresOrg,
	})
}

func NewCertPolicyRequiresOrg() lint.LintInterface {
	return &CertPolicyRequiresOrg{}
}

func (l *CertPolicyRequiresOrg) CheckApplies(cert *x509.Certificate) bool {
	return util.SliceContainsOID(cert.PolicyIdentifiers, util.BROrganizationValidatedOID) && !util.IsCACert(cert)
}

func (l *CertPolicyRequiresOrg) Execute(cert *x509.Certificate) *lint.LintResult {
	var out lint.LintResult
	if util.TypeInName(&cert.Subject, util.OrganizationNameOID) {
		out.Status = lint.Pass
	} else {
		out.Status = lint.Error
	}
	return &out
}
