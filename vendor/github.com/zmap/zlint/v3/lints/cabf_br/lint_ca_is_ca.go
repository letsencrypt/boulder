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
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/*
--- Citation History of this Requirement ---
v1.0 to v1.2.5: Appendix B §1(A) (roots) and §2(D) (subordinate CAs)
v1.3.0 to v1.8.7: §7.1.2.1(a) (roots) and §7.1.2.2(d) (subordinate CAs)
v2.0.0 to v2.1.7: §7.1.2.1.4 (roots) and §7.1.2.10.4 (all other CA profiles)

--- Version Notes ---
In v1.1.3, Appendix B's sections were numbered but retained their previous titles. "Root CA Certificate"
became section 1 and "Subordinate CA Certificate" became section 2. The numerical section references are
used here for all versions following the original document format of the Baseline Requirements.

This requirement was baselined at v2.2.6 and is current.

--- Requirements Language ---
BRs: 7.1.2.1.4 Root CA Basic Constraints
+-------------------+------------------+
| Field             | Description      |
+-------------------+------------------+
| cA                | MUST be set TRUE |
+-------------------+------------------+
| pathLenConstraint | NOT RECOMMENDED  |
+-------------------+------------------+

BRs: 7.1.2.10.4 CA Certificate Basic Constraints
+-------------------+------------------+
| Field             | Description      |
+-------------------+------------------+
| cA                | MUST be set TRUE |
+-------------------+------------------+
| pathLenConstraint | MAY be present   |
+-------------------+------------------+
*/

type caIsCA struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_ca_is_ca",
			Description:   "Root and Sub CA Certificate: The CA field MUST be set to true.",
			Citation:      "BRs: 7.1.2.1.4, 7.1.2.10.4",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABEffectiveDate,
		},
		Lint: NewCaIsCA,
	})
}

func NewCaIsCA() lint.LintInterface {
	return &caIsCA{}
}

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

func (l *caIsCA) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.KeyUsageOID) && c.KeyUsage&x509.KeyUsageCertSign != 0 && util.IsExtInCert(c, util.BasicConstOID)
}

func (l *caIsCA) Execute(c *x509.Certificate) *lint.LintResult {
	e := util.GetExtFromCert(c, util.BasicConstOID)
	var constraints basicConstraints
	_, err := asn1.Unmarshal(e.Value, &constraints)
	if err != nil {
		return &lint.LintResult{Status: lint.Fatal}
	}
	if constraints.IsCA {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Error}
	}
}
