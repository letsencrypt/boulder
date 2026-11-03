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
	"slices"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_duplicate_etsi_qcstatement",
			Description:   "Checks for any duplicated ETSI QcStatements",
			Citation:      "ETSI EN 319 412-5 v2.6.1, clause QCS-4.1-02A",
			Source:        lint.EtsiEsi,
			EffectiveDate: util.EtsiEn319_412_5_V2_6_1_Date,
		},
		Lint: NewDuplicateETSIQCStatement,
	})
}

type DuplicateETSIQCStatement struct{}

func NewDuplicateETSIQCStatement() lint.LintInterface {
	return &DuplicateETSIQCStatement{}
}

func (l *DuplicateETSIQCStatement) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.QcStateOid)
}

var etsiStatIds = []string{
	"0.4.0.1862.1.1", // id-etsi-qcs-QcCompliance
	"0.4.0.1862.1.2", // id-etsi-qcs-QcLimitValue
	"0.4.0.1862.1.3", // id-etsi-qcs-QcRetentionPeriod
	"0.4.0.1862.1.4", // id-etsi-qcs-QcSSCD
	"0.4.0.1862.1.5", // id-etsi-qcs-QcPDS
	"0.4.0.1862.1.6", // id-etsi-qcs-QcType
	"0.4.0.1862.1.7", // id-etsi-qcs-QcCClegislation
	"0.4.0.1862.1.8", // id-etsi-qcs-QcIdentMethod
	"0.4.0.1862.1.9", // id-etsi-qcs-QcQSCDlegislation
}

func (l *DuplicateETSIQCStatement) Execute(c *x509.Certificate) *lint.LintResult {

	foundStatements := make(map[string]bool)

	for _, statId := range c.QCStatements.StatementIDs {
		if foundStatements[statId] && slices.Contains(etsiStatIds, statId) {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "The qcStatements extn. shall not contain more than one instance of any qcStatement from ETSI EN 319 412‑5",
			}
		}
		foundStatements[statId] = true
	}
	return &lint.LintResult{Status: lint.Pass}
}
