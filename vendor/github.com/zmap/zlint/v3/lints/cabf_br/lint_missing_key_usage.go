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

package cabf_br

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "w_missing_key_usage",
			Description:   "Subscriber certificates SHOULD include the KeyUsage extension",
			Citation:      "CABF TLS BRs section 7.1.2.7.6 (Subscriber Certificate Extensions)",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_2_0_0_Date,
		},
		Lint: NewMissingKeyUsage,
	})
}

type MissingKeyUsage struct{}

func NewMissingKeyUsage() lint.LintInterface {
	return &MissingKeyUsage{}
}

func (l *MissingKeyUsage) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *MissingKeyUsage) Execute(c *x509.Certificate) *lint.LintResult {

	if !util.IsExtInCert(c, util.KeyUsageOID) {
		return &lint.LintResult{
			Status:  lint.Warn,
			Details: "Subscriber certificates SHOULD include the KeyUsage extension",
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
