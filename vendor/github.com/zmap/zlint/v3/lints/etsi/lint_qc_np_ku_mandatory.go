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
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type qcNaturalPersonKUMandatory struct{}

/************************************************
4.3.2 Key usage
The key usage extension shall be present and shall contain one (and only one) of the key usage settings defined in
table 1 (A, B, C, D, E or F). Type A, C or E should be used to avoid mixed usage of keys.
************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_etsi_natural_person_key_usage_mandatory",
			Description:   "The key usage extension shall be present for ETSI certificates issued to natural persons",
			Citation:      "ETSI EN 319 412-2 V2.2.1 (2020-07) / Section 4.3.2",
			Source:        lint.EtsiEsi,
			EffectiveDate: util.EtsiEn319_412_2_V2_2_1_Date,
		},
		Lint: NewQcNaturalPersonKUMandatory,
	})
}

func NewQcNaturalPersonKUMandatory() lint.LintInterface {
	return &qcNaturalPersonKUMandatory{}
}

func (l *qcNaturalPersonKUMandatory) CheckApplies(c *x509.Certificate) bool {
	return util.IsEtsiQcNaturalPerson(c) && util.IsSubscriberCert(c)
}

func (l *qcNaturalPersonKUMandatory) Execute(c *x509.Certificate) *lint.LintResult {
	if util.HasKeyUsageOID(c) {
		return &lint.LintResult{Status: lint.Pass}
	}
	return &lint.LintResult{Status: lint.Error, Details: "ETSI natural person certificates does not have the key usage extension"}

}
