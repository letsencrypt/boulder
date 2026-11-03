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

// psd2EuNcaIds is a dated snapshot of the European Banking Authority's
// "National identification codes to be used by qualified trust service
// providers for identification of competent authorities in an eIDAS
// certificate for PSD2 purposes," Version 4, published 2023-02-02:
// https://www.eba.europa.eu/sites/default/files/documents/10180/2882455/5dac742c-c39d-47b5-bd73-f8befb0d2338/NCA%20abbreviations%20for%20inclusion%20in%20eIDAS%20certificates.pdf
// See the init() comment below for why this makes the lint Warn, not
// Error. Keyed by country code, matching the lookup convention already
// used by util.IsISOCountryCode/util.HasValidTLD. IS and IE both
// use NCA code "CBI" (Central Bank of Iceland vs. Central Bank of
// Ireland) — not a typo, just two countries sharing an abbreviation; the
// map is keyed by country, so this causes no ambiguity.
var psd2EuNcaIds = map[string]string{
	"AT": "FMA", "BE": "NBB", "BG": "BNB", "HR": "HNB",
	"CY": "CBC", "CZ": "CNB", "DK": "DFSA", "EE": "FI",
	"FI": "FINFSA", "FR": "ACPR", "DE": "BAFIN", "GR": "BOG",
	"HU": "CBH", "IS": "CBI", "IE": "CBI", "IT": "BI",
	"LI": "FMA", "LV": "BL", "LT": "BL", "LU": "CSSF",
	"NO": "FSA", "MT": "MFSA", "NL": "DNB", "PL": "PFSA",
	"PT": "BP", "RO": "NBR", "SK": "NBS", "SI": "BS",
	"ES": "BE", "SE": "FINA",
}

type qcStatemPsd2NcaIdEulist struct{}

// ETSI TS 119 495 V1.8.1 (2026-04), Annex D (informative):
//
//	The current list of NCA abbreviations is published on the European
//	Banking Authority website. [...] NCAs can sometimes use underscore
//	("_") instead of hyphen-minus ("-"), but in the context of the
//	present document, hyphen-minus is required when linking country
//	code with an NCA identifier.
//
// The table above is a dated snapshot of that externally-maintained EBA
// document, not fixed spec text — unlike every other PSD2 lint's
// citation, this one can go stale independently of any ETSI TS 119 495
// edition change. That is exactly why this lint is Warn, not Error.
func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "w_qcstatem_psd2_ncaid_eulist",
			Description:   "Warns if the NCAId field of a PSD2 QcStatement has a country prefix matching an EU/EEA national competent authority, but the full value does not match that authority's current EBA-published code",
			Citation:      "ETSI TS 119 495 V1.8.1 (2026-04), Annex D; European Banking Authority, \"National identification codes to be used by qualified trust service providers for identification of competent authorities in an eIDAS certificate for PSD2 purposes,\" Version 4 (2023-02-02)",
			Source:        lint.EtsiEsi,
			EffectiveDate: util.EtsiTs119495_V1_2_1_Date,
		},
		Lint: NewQcStatemPsd2NcaIdEulist,
	})
}

func NewQcStatemPsd2NcaIdEulist() lint.LintInterface {
	return &qcStatemPsd2NcaIdEulist{}
}

func (l *qcStatemPsd2NcaIdEulist) CheckApplies(c *x509.Certificate) bool {
	if !util.IsExtInCert(c, util.QcStateOid) {
		return false
	}
	return util.ParseQcStatem(util.GetExtFromCert(c, util.QcStateOid).Value, util.IdEtsiPsd2Statem).IsPresent()
}

func (l *qcStatemPsd2NcaIdEulist) Execute(c *x509.Certificate) *lint.LintResult {
	ext := util.GetExtFromCert(c, util.QcStateOid)
	s := util.ParseQcStatem(ext.Value, util.IdEtsiPsd2Statem)
	if s.GetErrorInfo() != "" {
		return &lint.LintResult{Status: lint.Error, Details: s.GetErrorInfo()}
	}
	psd2, ok := s.(util.EtsiPsd2)
	if !ok {
		return &lint.LintResult{Status: lint.Fatal, Details: "parsed QC statement is not of type EtsiPsd2"}
	}

	ncaId := psd2.Decoded.NCAId
	// Require the well-formed "<country>-<code>" shape (hyphen at index 2)
	// before treating the first two characters as a country prefix. This
	// lint does not re-validate NCAId's syntax (that's
	// e_qcstatem_psd2_ncaid_format's job); a malformed value like
	// "NOTAVALIDID" must not be mistaken for country prefix "NO" and
	// compared against Norway's table entry.
	if len(ncaId) <= 2 || ncaId[2] != '-' {
		return &lint.LintResult{Status: lint.Pass}
	}
	countryPrefix := ncaId[:2]

	ncaCode, ok := psd2EuNcaIds[countryPrefix]
	if !ok {
		return &lint.LintResult{Status: lint.Pass}
	}
	expected := countryPrefix + "-" + ncaCode
	if ncaId != expected {
		return &lint.LintResult{Status: lint.Warn, Details: fmt.Sprintf(
			"NCAId %q does not match the current EU NCA identifier %q for country %s",
			ncaId, expected, countryPrefix)}
	}
	return &lint.LintResult{Status: lint.Pass}
}
