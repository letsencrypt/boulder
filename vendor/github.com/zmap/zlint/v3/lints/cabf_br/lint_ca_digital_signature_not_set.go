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

type caDigSignNotSet struct{}

/************************************************
--- Citation History of this Requirement ---
v1 to v1.2.5: Appendix B §1(B) (roots) and §2(E) (subordinate CAs)
v1.3.0 to v1.8.7: 7.1.2.1b (roots) and §7.1.2.2e (subordinate CAs)
v2.0.0 to v2.1.7: 7.1.2.10.7

--- Version Notes ---
In v1.1.3, Appendix B's sections were numbered but retained their previous titles. "Root CA Certificate"
became section 1 and "Subordinate CA Certificate" became section 2. The numerical section references are
used here for all versions following the original document format of the Baseline Requirements.

This requirement was baselined at v2.1.7 and is current.

--- Requirements Language ---
BRs: 7.1.2 "Certificate Content and Extensions"
If the CA asserts compliance with these Baseline Requirements, all certificates that it issues MUST
comply with one of the following certificate profiles, which incorporate, and are derived from RFC 5280.

[Each of the CA profiles specifies the keyUsage extension follows section 7.1.2.10.7]

BRs: 7.1.2.10.7 "CA Certificate Key Usage"
+------------------+-----------+----------+
| Key Usage        | Permitted | Required |
+------------------+-----------+----------+
| digitalSignature | Y         | N^15     |
+------------------+-----------+----------+
Footnote 15:
If a CA Certificate does not assert the digitalSignature bit, the CA Private Key MUST NOT be
used to sign an OCSP Response. See Section 7.3 for more information.
************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "n_ca_digital_signature_not_set",
			Description:   "Root and Subordinate CA Certificates that wish to use their private key for signing OCSP responses will not be able to without their digital signature set",
			Citation:      "BRs: 7.1.2.10.7",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABEffectiveDate,
		},
		Lint: NewCaDigSignNotSet,
	})
}

func NewCaDigSignNotSet() lint.LintInterface {
	return &caDigSignNotSet{}
}

func (l *caDigSignNotSet) CheckApplies(c *x509.Certificate) bool {
	return c.IsCA && util.IsExtInCert(c, util.KeyUsageOID)
}

func (l *caDigSignNotSet) Execute(c *x509.Certificate) *lint.LintResult {
	if c.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{
			Status:  lint.Notice,
			Details: "CA certificate does not assert digitalSignature and MUST NOT be used to sign OCSP responses",
		}
	}
}
