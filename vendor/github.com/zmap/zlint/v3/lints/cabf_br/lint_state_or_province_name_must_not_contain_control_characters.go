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
	"regexp"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	// The issue that was at play here was that CAs were accidentally injecting structured data (such as JSON
	// or key-value pairs) into the stateOrProvince field. This is not legal as stateOrProvince needs to be sourced
	// from an authoritative database if plain, human readable, names.
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_state_or_province_name_must_not_contain_control_characters",
			Description:   "stateOrProvinceName MUST come from an authoritative data source of plain, human readable, names",
			Citation:      "CABF/BRs 3.2.2.1",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABEffectiveDate,
		},
		Lint: NewStateOrProvinceNameMustNotContainControlCharacters,
	})
}

type StateOrProvinceNameMustNotContainControlCharacters struct{}

var controlCharsRegex = regexp.MustCompile(`[=:{};"|\\[\]]`)

func NewStateOrProvinceNameMustNotContainControlCharacters() lint.LintInterface {
	return &StateOrProvinceNameMustNotContainControlCharacters{}
}

func (l *StateOrProvinceNameMustNotContainControlCharacters) CheckApplies(c *x509.Certificate) bool {
	return true
}

func (l *StateOrProvinceNameMustNotContainControlCharacters) Execute(c *x509.Certificate) *lint.LintResult {
	for _, province := range c.Subject.Province {
		if controlCharsRegex.MatchString(province) {
			return &lint.LintResult{Status: lint.Error}
		}
	}
	for _, locality := range c.Subject.Locality {
		if controlCharsRegex.MatchString(locality) {
			return &lint.LintResult{Status: lint.Error}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
