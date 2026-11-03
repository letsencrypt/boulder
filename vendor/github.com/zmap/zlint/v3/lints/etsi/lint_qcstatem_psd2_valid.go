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

type qcStatemPsd2Valid struct{}

// ETSI TS 119 495 V1.8.1 (2026-04), Section 5.1:
//
//	GEN-5.1-3: The syntax of the defined statement shall comply with ASN.1 [6]. The
//	complete ASN.1 module for all defined statements shall be as provided in Annex A;
//	it takes precedence over the ASN.1 definition provided in the body of the present
//	document, in case of discrepancy.
//
// ETSI TS 119 495 V1.8.1 (2026-04), Annex A (normative): ASN.1 Declaration:
//
//	PSD2QcType ::= SEQUENCE{
//	    rolesOfPSP  RolesOfPSP,
//	    nCAName     NCAName,
//	    nCAId       NCAId }
//
//	NCAName ::= UTF8String (SIZE(1..256))
//	NCAId ::= UTF8String (SIZE(1..256))
//
//	RolesOfPSP ::= SEQUENCE OF RoleOfPSP
//
//	RoleOfPSP ::= SEQUENCE{
//	    roleOfPspOid    RoleOfPspOid,
//	    roleOfPspName   RoleOfPspName}
func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_qcstatem_psd2_valid",
			Description:   "Checks that a QC Statement of the type id-etsi-psd2-qcStatement has the correct ASN.1 encoding",
			Citation:      "ETSI TS 119 495 V1.8.1 (2026-04), Section 5.1, GEN-5.1-3, and Annex A (normative): ASN.1 Declaration",
			Source:        lint.EtsiEsi,
			EffectiveDate: util.EtsiTs119495_V1_1_2_Date,
		},
		Lint: NewQcStatemPsd2Valid,
	})
}

func NewQcStatemPsd2Valid() lint.LintInterface {
	return &qcStatemPsd2Valid{}
}

func (l *qcStatemPsd2Valid) CheckApplies(c *x509.Certificate) bool {
	if !util.IsExtInCert(c, util.QcStateOid) {
		return false
	}
	return util.ParseQcStatem(util.GetExtFromCert(c, util.QcStateOid).Value, util.IdEtsiPsd2Statem).IsPresent()
}

func (l *qcStatemPsd2Valid) Execute(c *x509.Certificate) *lint.LintResult {
	ext := util.GetExtFromCert(c, util.QcStateOid)
	s := util.ParseQcStatem(ext.Value, util.IdEtsiPsd2Statem)
	if s.GetErrorInfo() != "" {
		return &lint.LintResult{Status: lint.Error, Details: s.GetErrorInfo()}
	}
	return &lint.LintResult{Status: lint.Pass}
}
