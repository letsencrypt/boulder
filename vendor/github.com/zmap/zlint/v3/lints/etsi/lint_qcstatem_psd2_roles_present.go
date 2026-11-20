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

type qcStatemPsd2RolesPresent struct{}

// ETSI TS 119 495 V1.8.1 (2026-04), Section 5.2.2:
//
//	GEN-5.2.2-1: RolesOfPSP shall contain one or more roles or contain a
//	single entry indicating that the role is unspecified. The roles shall
//	be as declared by a Competent Authority via its public records for the
//	subject PSP. Each role is represented by a role ASN.1 Object Identifier
//	and a name string.
func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_qcstatem_psd2_roles_present",
			Description:   "Checks that the RolesOfPSP field of a PSD2 QcStatement contains at least one role",
			Citation:      "ETSI TS 119 495 V1.8.1 (2026-04), Section 5.2.2, GEN-5.2.2-1",
			Source:        lint.EtsiEsi,
			EffectiveDate: util.EtsiTs119495_V1_1_2_Date,
		},
		Lint: NewQcStatemPsd2RolesPresent,
	})
}

func NewQcStatemPsd2RolesPresent() lint.LintInterface {
	return &qcStatemPsd2RolesPresent{}
}

func (l *qcStatemPsd2RolesPresent) CheckApplies(c *x509.Certificate) bool {
	if !util.IsExtInCert(c, util.QcStateOid) {
		return false
	}
	return util.ParseQcStatem(util.GetExtFromCert(c, util.QcStateOid).Value, util.IdEtsiPsd2Statem).IsPresent()
}

func (l *qcStatemPsd2RolesPresent) Execute(c *x509.Certificate) *lint.LintResult {
	ext := util.GetExtFromCert(c, util.QcStateOid)
	s := util.ParseQcStatem(ext.Value, util.IdEtsiPsd2Statem)
	if s.GetErrorInfo() != "" {
		return &lint.LintResult{Status: lint.Error, Details: s.GetErrorInfo()}
	}
	psd2, ok := s.(util.EtsiPsd2)
	if !ok {
		return &lint.LintResult{Status: lint.Fatal, Details: "parsed QC statement is not of type EtsiPsd2"}
	}

	if len(psd2.Decoded.RolesOfPSP) == 0 {
		return &lint.LintResult{Status: lint.Error, Details: "RolesOfPSP must contain at least one role"}
	}
	return &lint.LintResult{Status: lint.Pass}
}
