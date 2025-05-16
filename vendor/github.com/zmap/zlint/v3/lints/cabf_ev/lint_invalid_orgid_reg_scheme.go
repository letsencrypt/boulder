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

// Contributed by <asantoni64@gmail.com>

package cabf_ev

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"fmt"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_ev_invalid_orgid_reg_scheme",
			Description:   "The Registration Schemes allowed in organizationIdentifier are those listed in Appendix H",
			Citation:      "CABF EV Guidelines §9.2.8",
			Source:        lint.CABFEVGuidelines,
			EffectiveDate: util.CABV170Date,
		},
		Lint: NewInvalidOrgIDRegistrationScheme,
	})
}

type invalidOrgIDRegistrationScheme struct{}

func NewInvalidOrgIDRegistrationScheme() lint.LintInterface {
	return &invalidOrgIDRegistrationScheme{}
}

func (l *invalidOrgIDRegistrationScheme) CheckApplies(c *x509.Certificate) bool {
	return util.IsEV(c.PolicyIdentifiers) && util.IsSubscriberCert(c) && c.Subject.OrganizationIDs != nil
}

func (l *invalidOrgIDRegistrationScheme) Execute(c *x509.Certificate) *lint.LintResult {

	if len(c.Subject.OrganizationIDs) == 0 {
		return &lint.LintResult{Status: lint.Pass}
	}

	// Let's assume there is just one OrganizationID; if not so, it's not this lint's business to raise an alarm
	orgId := c.Subject.OrganizationIDs[0]

	runes := []rune(orgId)

	if len(runes) < 3 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Invalid registration scheme in Subject.organizationIdentifier",
		}
	}

	firstThreeRunes := runes[:3]
	registrationScheme := string(firstThreeRunes)

	if (registrationScheme != "NTR") && (registrationScheme != "VAT") && (registrationScheme != "PSD") {
		return &lint.LintResult{
			Status: lint.Error,
			Details: fmt.Sprintf("Registration scheme '%s' in Subject.organizationIdentifier "+
				"is not allowed in EV certificates", registrationScheme),
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
