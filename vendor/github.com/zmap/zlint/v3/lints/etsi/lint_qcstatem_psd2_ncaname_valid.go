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
	"unicode/utf8"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type qcStatemPsd2NcaNameValid struct{}

// ETSI TS 119 495 V1.8.1 (2026-04), Section 5.2.3:
//
//	GEN-5.2.3-1: The NCAName shall be plain text using Latin alphabet
//	provided by the Competent Authority itself for purpose of
//	identification in certificates.
//
//	NCAName ::= UTF8String (SIZE(1..256))
//
//	GEN-5.2.3-1A: If the subject role is international central bank
//	(PSP_CB) or international public authority (PSP_PA), NCAName shall
//	have the value "NA".
func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_qcstatem_psd2_ncaname_valid",
			Description:   "Checks that the NCAName field of a PSD2 QcStatement is non-empty and at most 256 characters, or 'NA' for a certificate declaring a PSP_CB or PSP_PA role",
			Citation:      "ETSI TS 119 495 V1.8.1 (2026-04), Section 5.2.3, GEN-5.2.3-1, GEN-5.2.3-1A",
			Source:        lint.EtsiEsi,
			EffectiveDate: util.EtsiTs119495_V1_1_2_Date,
		},
		Lint: NewQcStatemPsd2NcaNameValid,
	})
}

func NewQcStatemPsd2NcaNameValid() lint.LintInterface {
	return &qcStatemPsd2NcaNameValid{}
}

func (l *qcStatemPsd2NcaNameValid) CheckApplies(c *x509.Certificate) bool {
	if !util.IsExtInCert(c, util.QcStateOid) {
		return false
	}
	return util.ParseQcStatem(util.GetExtFromCert(c, util.QcStateOid).Value, util.IdEtsiPsd2Statem).IsPresent()
}

func (l *qcStatemPsd2NcaNameValid) Execute(c *x509.Certificate) *lint.LintResult {
	ext := util.GetExtFromCert(c, util.QcStateOid)
	s := util.ParseQcStatem(ext.Value, util.IdEtsiPsd2Statem)
	psd2, ok := s.(util.EtsiPsd2)
	if !ok {
		return &lint.LintResult{Status: lint.Fatal, Details: "parsed QC statement is not of type EtsiPsd2"}
	}

	// Check NCAName itself against psd2.Decoded (populated whenever the
	// PSD2QcType SEQUENCE itself unmarshaled, even if e_qcstatem_psd2_valid's
	// structural SIZE(1..256) check already flagged it) before falling back
	// to s.GetErrorInfo()'s generic message, so this lint's own
	// NCAName-specific Details take precedence over that structural check.
	if util.IsPsd2CentralBankOrPublicAuthority(psd2.Decoded.RolesOfPSP) {
		if psd2.Decoded.NCAName != "NA" {
			return &lint.LintResult{Status: lint.Error, Details: "NCAName must be 'NA' for a PSD2 QcStatement declaring a PSP_CB or PSP_PA role"}
		}
	} else {
		nameLen := utf8.RuneCountInString(psd2.Decoded.NCAName)
		if nameLen == 0 {
			return &lint.LintResult{Status: lint.Error, Details: "NCAName must not be empty"}
		}
		if nameLen > 256 {
			return &lint.LintResult{Status: lint.Error, Details: "NCAName must be at most 256 characters"}
		}
	}

	if s.GetErrorInfo() != "" {
		return &lint.LintResult{Status: lint.Error, Details: s.GetErrorInfo()}
	}
	return &lint.LintResult{Status: lint.Pass}
}
