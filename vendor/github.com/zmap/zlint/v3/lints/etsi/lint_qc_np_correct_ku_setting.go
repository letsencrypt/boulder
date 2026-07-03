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

package etsi

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type qcNaturalPersonKUCorrectSetting struct{}

/************************************************
4.3.2 Key usage
The key usage extension shall be present and shall contain one (and only one) of the key usage settings defined in
table 1 (A, B, C, D, E or F). Type A, C or E should be used to avoid mixed usage of keys.
************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_etsi_natural_person_key_usage_correct_values",
			Description:   "The key usage extension shall contain a valid key usage setting for ETSI certificates issued to natural persons",
			Citation:      "ETSI EN 319 412-2 V2.2.1 (2020-07) / Section 4.3.2",
			Source:        lint.EtsiEsi,
			EffectiveDate: util.EtsiEn319_412_2_V2_2_1_Date,
		},
		Lint: NewQcNaturalPersonKUCorrectSetting,
	})
}

func NewQcNaturalPersonKUCorrectSetting() lint.LintInterface {
	return &qcNaturalPersonKUCorrectSetting{}
}

func (l *qcNaturalPersonKUCorrectSetting) CheckApplies(c *x509.Certificate) bool {
	return util.IsEtsiQcNaturalPerson(c) && util.HasKeyUsageOID(c) && util.IsSubscriberCert(c)
}

func (l *qcNaturalPersonKUCorrectSetting) Execute(c *x509.Certificate) *lint.LintResult {

	if c.KeyUsage == x509.KeyUsageContentCommitment { // Type A
		return &lint.LintResult{Status: lint.Pass}
	}
	if c.KeyUsage == (x509.KeyUsageContentCommitment | x509.KeyUsageDigitalSignature) { // Type B
		return &lint.LintResult{Status: lint.Pass}
	}
	if c.KeyUsage == x509.KeyUsageDigitalSignature { // Type C
		return &lint.LintResult{Status: lint.Pass}
	}
	if c.KeyUsage == (x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment) { //Type D, Option 1
		return &lint.LintResult{Status: lint.Pass}
	}
	if c.KeyUsage == (x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement) { //Type D, Option 2
		return &lint.LintResult{Status: lint.Pass}
	}
	if c.KeyUsage == x509.KeyUsageKeyEncipherment { //Type E, Option 1
		return &lint.LintResult{Status: lint.Pass}
	}
	if c.KeyUsage == x509.KeyUsageKeyAgreement { //Type E, Option 2
		return &lint.LintResult{Status: lint.Pass}
	}
	if c.KeyUsage == (x509.KeyUsageContentCommitment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment) { //Type F, Option 1
		return &lint.LintResult{Status: lint.Pass}
	}
	if c.KeyUsage == (x509.KeyUsageContentCommitment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement) { //Type F, Option 2
		return &lint.LintResult{Status: lint.Pass}
	}

	return &lint.LintResult{
		Status:  lint.Error,
		Details: fmt.Sprintf("KeyUsage %v (%08b) is not allowed for ETSI natural person certificates", util.GetKeyUsageStrings(c.KeyUsage), c.KeyUsage),
	}

}
