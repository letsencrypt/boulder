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

package community

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"regexp"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_subj_country_not_uppercase",
			Description:   "Alpha-2 country codes shall consist of LATIN CAPITAL LETTER A through LATIN CAPITAL LETTER Z",
			Citation:      "ISO 3166-2:2020(E) section 5.1",
			Source:        lint.Community,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewSubjCountryNotUppercase,
	})
}

type subjCountryNotUppercase struct{}

func NewSubjCountryNotUppercase() lint.LintInterface {
	return &subjCountryNotUppercase{}
}

func (l *subjCountryNotUppercase) CheckApplies(c *x509.Certificate) bool {
	return true
}

var re = regexp.MustCompile("^[A-Z]+$")

func (l *subjCountryNotUppercase) Execute(c *x509.Certificate) *lint.LintResult {
	// There should be only one countryName attribute in the Subject, normally,
	// but checking this is not our business here, so let's scan them all
	for _, cc := range c.Subject.Country {
		if !re.MatchString(cc) {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "Country codes must be comprised of uppercase A-Z letters",
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
