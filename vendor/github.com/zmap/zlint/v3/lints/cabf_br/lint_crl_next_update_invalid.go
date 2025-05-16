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
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"fmt"
)

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_crl_next_update_invalid",
			Description:   "For CRLs covering (EE|CA) certificates, nextUpdate must be at most (10 days|12 months) beyond thisUpdate",
			Citation:      "Section 4.9.7 of BRs v1.8.7 (then section 7.2 since BRs v2.0.0)",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_1_8_7_Date,
		},
		Lint: NewCrlNextUpdateInvalid,
	})
}

type CrlNextUpdateInvalid struct {
	SubscriberCRL bool `comment:"Set this to false if the CRL to be linted covers CA certificates"`
}

func (l *CrlNextUpdateInvalid) Configure() interface{} {
	return l
}

func NewCrlNextUpdateInvalid() lint.RevocationListLintInterface {
	return &CrlNextUpdateInvalid{
		SubscriberCRL: true,
	}
}

func (l *CrlNextUpdateInvalid) CheckApplies(c *x509.RevocationList) bool {
	// If NextUpdate is absent it's an error but it's not this lint's business
	return !c.NextUpdate.IsZero()
}

func (l *CrlNextUpdateInvalid) Execute(c *x509.RevocationList) *lint.LintResult {

	// As set out in the CABF BRs
	CabfMaxEECRLValidityDays := 10
	CabfMaxCACRLValidityMonths := 12

	if l.SubscriberCRL {
		if c.NextUpdate.After(c.ThisUpdate.AddDate(0, 0, CabfMaxEECRLValidityDays)) {
			return &lint.LintResult{
				Status: lint.Error,
				Details: fmt.Sprintf(
					"For CRLs covering Subscriber Certificates, nextUpdate must be at most %d days after thisUpdate",
					CabfMaxEECRLValidityDays),
			}
		}
	} else {
		if c.NextUpdate.After(c.ThisUpdate.AddDate(0, CabfMaxCACRLValidityMonths, 0)) {
			return &lint.LintResult{
				Status: lint.Error,
				Details: fmt.Sprintf(
					"For CRLs covering CA Certificates, nextUpdate must be at most %d months after thisUpdate",
					CabfMaxCACRLValidityMonths),
			}
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
