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
	"regexp"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

var psd2NcaIdFormat = regexp.MustCompile(`^[A-Z]{2}-[A-Z]{2,8}$`)

type qcStatemPsd2NcaIdFormat struct{}

// ETSI TS 119 495 V1.8.1 (2026-04), Section 5.2.3:
//
//	GEN-5.2.3-2: The NCAId shall contain information using the following
//	structure in the presented order:
//	  - 2 character ISO 3166-1 country code representing the Competent
//	    Authority country;
//	  - hyphen-minus "-" (0x2D (ASCII), U+002D (UTF-8)); and
//	  - 2-8 character Competent Authority identifier without country code
//	    (A-Z uppercase only, no separator).
//
//	GEN-5.2.3-5: If the subject role is international central bank (PSP_CB)
//	or international public authority (PSP_PA), NCAId shall have the value
//	"NA".
func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_qcstatem_psd2_ncaid_format",
			Description:   "Checks that the NCAId field of a PSD2 QcStatement has the correct syntax: a 2-letter ISO 3166-1 country code, a hyphen, and a 2-8 character uppercase identifier, or 'NA' for a certificate declaring a PSP_CB or PSP_PA role",
			Citation:      "ETSI TS 119 495 V1.8.1 (2026-04), Section 5.2.3, GEN-5.2.3-2, GEN-5.2.3-5",
			Source:        lint.EtsiEsi,
			EffectiveDate: util.EtsiTs119495_V1_1_2_Date,
		},
		Lint: NewQcStatemPsd2NcaIdFormat,
	})
}

func NewQcStatemPsd2NcaIdFormat() lint.LintInterface {
	return &qcStatemPsd2NcaIdFormat{}
}

func (l *qcStatemPsd2NcaIdFormat) CheckApplies(c *x509.Certificate) bool {
	if !util.IsExtInCert(c, util.QcStateOid) {
		return false
	}
	return util.ParseQcStatem(util.GetExtFromCert(c, util.QcStateOid).Value, util.IdEtsiPsd2Statem).IsPresent()
}

func (l *qcStatemPsd2NcaIdFormat) Execute(c *x509.Certificate) *lint.LintResult {
	ext := util.GetExtFromCert(c, util.QcStateOid)
	s := util.ParseQcStatem(ext.Value, util.IdEtsiPsd2Statem)
	if s.GetErrorInfo() != "" {
		return &lint.LintResult{Status: lint.Error, Details: s.GetErrorInfo()}
	}
	psd2, ok := s.(util.EtsiPsd2)
	if !ok {
		return &lint.LintResult{Status: lint.Fatal, Details: "parsed QC statement is not of type EtsiPsd2"}
	}

	if util.IsPsd2CentralBankOrPublicAuthority(psd2.Decoded.RolesOfPSP) {
		if psd2.Decoded.NCAId != "NA" {
			return &lint.LintResult{Status: lint.Error, Details: "NCAId must be 'NA' for a PSD2 QcStatement declaring a PSP_CB or PSP_PA role"}
		}
		return &lint.LintResult{Status: lint.Pass}
	}

	if !psd2NcaIdFormat.MatchString(psd2.Decoded.NCAId) {
		return &lint.LintResult{Status: lint.Error, Details: "NCAId must be a 2-letter ISO 3166-1 country code, a hyphen, and a 2-8 character uppercase identifier"}
	}
	if !util.IsISOCountryCode(psd2.Decoded.NCAId[:2]) {
		return &lint.LintResult{Status: lint.Error, Details: "NCAId country code prefix is not an assigned ISO 3166-1 country code"}
	}
	return &lint.LintResult{Status: lint.Pass}
}
