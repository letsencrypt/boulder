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

/*
 * Contributed by Adriano Santoni <adriano.santoni@staff.aruba.it>
 * of ACTALIS S.p.A. (www.actalis.com).
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
			Name:          "e_ev_invalid_business_category",
			Description:   "Checks that businessCategory contains a valid value as per EV Guidelines 7.1.4.2.3",
			Citation:      "EVGs 7.1.4.2.3",
			Source:        lint.CABFEVGuidelines,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewInvalidBusinessCategory,
	})
}

type invalidBusinessCategory struct{}

func NewInvalidBusinessCategory() lint.LintInterface {
	return &invalidBusinessCategory{}
}

func (l *invalidBusinessCategory) CheckApplies(c *x509.Certificate) bool {
	return util.IsEV(c.PolicyIdentifiers) && util.IsSubscriberCert(c)
}

func (l *invalidBusinessCategory) Execute(c *x509.Certificate) *lint.LintResult {

	for _, v := range c.Subject.Names {
		if util.BusinessOID.Equal(v.Type) {
			businessCategory := v.Value
			if (businessCategory == "Private Organization") ||
				(businessCategory == "Government Entity") ||
				(businessCategory == "Business Entity") ||
				(businessCategory == "Non-Commercial Entity") {
				return &lint.LintResult{Status: lint.Pass}
			} else {
				return &lint.LintResult{Status: lint.Error}
			}
		}
	}

	// businessCategory missing: that's an error, but is not this lint's business
	return &lint.LintResult{Status: lint.NA}
}
