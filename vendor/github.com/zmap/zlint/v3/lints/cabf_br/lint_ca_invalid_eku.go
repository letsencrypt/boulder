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
 * Contributed by Adriano Santoni <asantoni64@gmail.com>
 */

package cabf_br

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_ca_invalid_eku",
			Description:   "Checks that SubCA certificates do not contain forbidden values in their EKU extension.",
			Citation:      "CABF BRs §7.1.2",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_1_7_1_Date,
		},
		Lint: NewCaInvalidEKU,
	})
}

type caInvalidEKU struct{}

func NewCaInvalidEKU() lint.LintInterface {
	return &caInvalidEKU{}
}

// This lint applies to any SubCA certificate to which the CABF BRs are applicable and which contains
// the EKU extension. Given that the lint source is lint.CABFBaselineRequirements, if we arrive here
// it's been already checked that the certificate falls within the purview of the CABF BRs.
func (l *caInvalidEKU) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubCA(c) && len(c.ExtKeyUsage) != 0
}

func (l *caInvalidEKU) Execute(c *x509.Certificate) *lint.LintResult {

	// If the EKU contains anyExtendedKeyUsage, it's probably a cross-certicate
	// In this case, the EKU must not contain any other value
	if util.HasEKU(c, x509.ExtKeyUsageAny) && len(c.ExtKeyUsage) > 1 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "anyExtendedKeyUsage MUST NOT be accompanied by any other value in the EKU extension",
		}
	}

	// If we get here, it is necessarily a SubCA with serverAuth in the EKU
	for _, eku := range c.ExtKeyUsage {
		if eku == x509.ExtKeyUsageEmailProtection ||
			eku == x509.ExtKeyUsageCodeSigning ||
			eku == x509.ExtKeyUsageTimeStamping ||
			eku == x509.ExtKeyUsageOcspSigning {

			return &lint.LintResult{
				Status:  lint.Error,
				Details: util.GetEKUString(eku) + "%s MUST not be present together with serverAuth in the EKU extension",
			}
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
