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

package cabf_ev

import (
	"fmt"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
	"strings"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cabf_org_identifier_joic_mismatch",
			Description:   "The cabfOrganizationIdentifier field country mismatches the JOI country in the subject DN",
			Citation:      "7.1.2.2",
			Source:        lint.CABFEVGuidelines,
			EffectiveDate: util.SC17EffectiveDate,
		},
		Lint: NewCabfOrgIdentifierJoicMismatch,
	})
}

type CabfOrgIdentifierJoicMismatch struct{}

func NewCabfOrgIdentifierJoicMismatch() lint.LintInterface {
	return &CabfOrgIdentifierJoicMismatch{}
}

func (l *CabfOrgIdentifierJoicMismatch) CheckApplies(c *x509.Certificate) bool {
	for _, ext := range c.Extensions {
		if ext.Id.Equal(util.CabfExtensionOrganizationIdentifier) {
			return true
		}
	}
	return false
}

func (l *CabfOrgIdentifierJoicMismatch) Execute(c *x509.Certificate) *lint.LintResult {

	joiCs := c.Subject.JurisdictionCountry

	for _, joi := range joiCs {
		if !strings.EqualFold(joi, c.CABFOrganizationIdentifier.Country) {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: fmt.Sprintf("cabfOrganizationIdentifier country %q does not match subject:jurisdictionCountry %q", c.CABFOrganizationIdentifier.Country, joi),
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
