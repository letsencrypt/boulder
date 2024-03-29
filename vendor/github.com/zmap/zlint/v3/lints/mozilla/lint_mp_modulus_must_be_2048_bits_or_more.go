/*
 * ZLint Copyright 2023 Regents of the University of Michigan
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

package mozilla

import (
	"crypto/rsa"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type modulus2048OrMore struct{}

/********************************************************************
Section 5.1 - Algorithms
RSA keys whose modulus size in bits is divisible by 8, and is at least 2048.
********************************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_mp_modulus_must_be_2048_bits_or_more",
			Description:   "RSA keys must have modulus size of at least 2048 bits",
			Citation:      "Mozilla Root Store Policy / Section 5.1",
			Source:        lint.MozillaRootStorePolicy,
			EffectiveDate: util.MozillaPolicy24Date,
		},
		Lint: NewModulus2048OrMore,
	})
}

func NewModulus2048OrMore() lint.LintInterface {
	return &modulus2048OrMore{}
}

func (l *modulus2048OrMore) CheckApplies(c *x509.Certificate) bool {
	return c.PublicKeyAlgorithm == x509.RSA
}

func (l *modulus2048OrMore) Execute(c *x509.Certificate) *lint.LintResult {
	pubKey, ok := c.PublicKey.(*rsa.PublicKey)
	if !ok {
		return &lint.LintResult{
			Status:  lint.Fatal,
			Details: "certificate public key was not an RSA public key",
		}
	}

	if bitLen := pubKey.N.BitLen(); bitLen < 2048 {
		return &lint.LintResult{Status: lint.Error}
	}

	return &lint.LintResult{Status: lint.Pass}
}
