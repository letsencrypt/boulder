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

	"time"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_excessively backdated",
			Description:   "notBefore [must be] a value within 48 hours of the certificate signing",
			Citation:      "TLS BRs §7.1.2.7",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.SC62EffectiveDate,
		},
		Lint: NewExcessivelyBackdated,
	})
}

type ExcessivelyBackdated struct{}

func NewExcessivelyBackdated() lint.LintInterface {
	return &ExcessivelyBackdated{}
}

func (l *ExcessivelyBackdated) CheckApplies(c *x509.Certificate) bool {

	return len(c.SignedCertificateTimestampList) > 0
}

func (l *ExcessivelyBackdated) Execute(c *x509.Certificate) *lint.LintResult {

	// The notBefore must be within 48 hours of the certificate signing (TLS BRs §7.1.2.7)
	// (and the signing time cannot be earlier than the timestamp contained in any SCTs)
	var maxDelayHours float64 = 48

	for _, sct := range c.SignedCertificateTimestampList {

		t := time.UnixMilli(int64(sct.Timestamp))
		deltaTime := t.Sub(c.NotBefore)
		deltaHours := deltaTime.Hours()

		if deltaHours > maxDelayHours {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "The Certificate's notBefore is more than 48 hours older than at least one embedded SCT",
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
