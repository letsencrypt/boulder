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
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cabf_org_identifier_psd_vat_has_state",
			Description:   "The cabfOrganizationIdentifier field for PSD org VAT Registration Schemes cannot include the referenceStateOrProvince field.",
			Citation:      "9.2.8",
			Source:        lint.CABFEVGuidelines,
			EffectiveDate: util.SC17EffectiveDate,
		},
		Lint: NewCabfOrgIdentifierPsdVatHasState,
	})
}

type CabfOrgIdentifierPsdVatHasState struct{}

func NewCabfOrgIdentifierPsdVatHasState() lint.LintInterface {
	return &CabfOrgIdentifierPsdVatHasState{}
}

func (l *CabfOrgIdentifierPsdVatHasState) CheckApplies(c *x509.Certificate) bool {
	for _, ext := range c.Extensions {
		if ext.Id.Equal(util.CabfExtensionOrganizationIdentifier) && (c.CABFOrganizationIdentifier.Scheme == "PSD" || c.CABFOrganizationIdentifier.Scheme == "VAT") {
			return true
		}
	}
	return false
}

func (l *CabfOrgIdentifierPsdVatHasState) Execute(c *x509.Certificate) *lint.LintResult {
	if c.CABFOrganizationIdentifier.State == "" {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Error}
	}
}
