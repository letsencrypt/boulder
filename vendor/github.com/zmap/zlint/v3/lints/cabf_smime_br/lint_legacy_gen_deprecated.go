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

package cabf_smime_br

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_legacy_generation_deprecated",
			Description:   "S/MIME Subscriber Certificates SHALL NOT be issued using the Legacy Generation profiles",
			Citation:      "CABF SMIME BRs v1.0.6 implementing the results of ballot SMC08",
			Source:        lint.CABFSMIMEBaselineRequirements,
			EffectiveDate: util.SMC08EffectiveDate,
		},
		Lint: NewLegacyGenerationDeprecated,
	})
}

type LegacyGenerationDeprecated struct{}

func NewLegacyGenerationDeprecated() lint.LintInterface {
	return &LegacyGenerationDeprecated{}
}

func (l *LegacyGenerationDeprecated) CheckApplies(c *x509.Certificate) bool {
	return util.IsLegacySMIMECertificate(c)
}

func (l *LegacyGenerationDeprecated) Execute(c *x509.Certificate) *lint.LintResult {
	return &lint.LintResult{
		Status: lint.Error,
		Details: "Legacy generation S/MIME policies are deprecated since " +
			util.SMC08EffectiveDate.Format("January 2, 2006"),
	}
}
