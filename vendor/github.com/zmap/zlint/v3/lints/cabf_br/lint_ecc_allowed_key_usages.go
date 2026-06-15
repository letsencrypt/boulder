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

/*
7.1.2.7.11 Subscriber Certificate Key Usage
The acceptable Key Usage values vary based on whether the Certificate’s
subjectPublicKeyInfo identifies an RSA public key or an ECC public key. CAs MUST ensure
the Key Usage is appropriate for the Certificate Public Key.

Table 56: Key Usage for ECC Public Keys

	+-------------------+-----------+------------------+
	| Key Usage         | Permitted | Required         |
	+-------------------+-----------+------------------+
	| digitalSignature  | Y         | MUST             |
	| nonRepudiation    | N         | –                |
	| keyEncipherment   | N         | –                |
	| dataEncipherment  | N         | –                |
	| keyAgreement      | Y         | NOT RECOMMENDED  |
	| keyCertSign       | N         | –                |
	| cRLSign           | N         | –                |
	| encipherOnly      | N         | –                |
	| decipherOnly      | N         | –                |
	+-------------------+-----------+------------------+
*/
func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cabf_ecc_allowed_key_usages",
			Description:   "For certificates with ECC public keys, digitalSignature MUST be present and only digitalSignature and keyAgreement key usages are allowed.",
			Citation:      "Section 7.1.2.7.11",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_2_0_0_Date, // This specific table exists in the CABF BRs as early as 2.0.0
		},
		Lint: NewEccAllowedKU,
	})
}

type eccAllowedKU struct{}

func NewEccAllowedKU() lint.LintInterface {
	return &eccAllowedKU{}
}

// CheckApplies returns true when the certificate has an ECC public key and a key usage extension.
func (l *eccAllowedKU) CheckApplies(c *x509.Certificate) bool {
	return c.PublicKeyAlgorithm == x509.ECDSA && util.HasKeyUsageOID(c)
}

func (l *eccAllowedKU) Execute(c *x509.Certificate) *lint.LintResult {
	allowedKeyUsages := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement

	if c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "DigitalSignature key usage is required for certificates with ECC public keys",
		}
	}

	if c.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
		return &lint.LintResult{
			Status:  lint.Warn,
			Details: "KeyAgreement key usage is not recommended for certificates with ECC public keys",
		}
	}

	if c.KeyUsage & ^allowedKeyUsages != 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Only DigitalSignature and KeyAgreement key usages are allowed for certificates with ECC public keys",
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
