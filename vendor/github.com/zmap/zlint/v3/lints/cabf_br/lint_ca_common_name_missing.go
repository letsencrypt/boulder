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

/*
--- Citation History of this Requirement ---
v1.4.8 to v1.8.7: 7.1.4.3.1a
v2.0.0 to v2.1.6: 7.1.2.10.2

--- Version Notes ---
As of v2.0.0, this requirement no longer applies to CA certificates that conform to the Cross-Certified
Subordinate CA Certificate Profile. This lint uses the global CrossSignedCa setting to determine if the
certificate under test should be treated as an exempt cross-signed CA. It does not attempt to determine
if the issuance date is after CABFBRs_2_0_0_Date because CAs are permitted to back-date the notBefore
to that of the earliest existing certificate under section 7.1.2.2.1

This requirement was baselined at v2.1.6 and is current.

--- Requirements Language ---
BRs: 7.1.2
If the CA asserts compliance with these Baseline Requirements, all certificates that it issues MUST
comply with one of the following certificate profiles

[Each of the CA profiles, excepting the Cross-Certified Subordinate CA Certificate Profile,
specifies the subject follows 7.1.2.10.2]

BRs: 7.1.2.10.2
The following table details the acceptable AttributeTypes that may appear within the type
field of an AttributeTypeAndValue, as well as the contents permitted within the value field.
+----------------+----------+----------------------------------------------------------+----------------+
| Attribute Name | Presence | Value                                                    | Verification   |
+----------------+----------+----------------------------------------------------------+----------------+
| commonName     | MUST     | The contents SHOULD be an identifier for the certificate |                |
|                |          | such that the certificate’s Name is unique across all    |                |
|                |          | certificates issued by the issuing certificate.          |                |
+----------------+----------+----------------------------------------------------------+----------------+
*/

type caCommonNameMissing struct {
	TlsBrConfig *lint.CABFBaselineRequirementsConfig
}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_ca_common_name_missing",
			Description:   "CA Certificates common name MUST be included.",
			Citation:      "BRs: 7.1.2.10.2",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABV148Date,
		},
		Lint: NewCaCommonNameMissing,
	})
}

func NewCaCommonNameMissing() lint.LintInterface {
	return &caCommonNameMissing{}
}

func (l *caCommonNameMissing) Configure() interface{} {
	return l
}

func (l *caCommonNameMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsCACert(c) && (l.TlsBrConfig == nil || !l.TlsBrConfig.CrossSignedCa)
}

func (l *caCommonNameMissing) Execute(c *x509.Certificate) *lint.LintResult {
	if c.Subject.CommonName == "" {
		return &lint.LintResult{Status: lint.Error}
	} else {
		return &lint.LintResult{Status: lint.Pass}
	}
}
