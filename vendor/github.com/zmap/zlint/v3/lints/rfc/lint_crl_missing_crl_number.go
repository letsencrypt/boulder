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

package rfc

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_crl_missing_crl_number",
			Description:   "CRL issuers conforming to this profile MUST include this extension in all CRLs",
			Citation:      "RFC5280 §5.2.3",
			Source:        lint.RFC5280,
			EffectiveDate: util.RFC5280Date,
		},
		Lint: NewMissingCRLNumber,
	})
}

type missingCRLNumber struct{}

func NewMissingCRLNumber() lint.RevocationListLintInterface {
	return &missingCRLNumber{}
}

func (l *missingCRLNumber) CheckApplies(c *x509.RevocationList) bool {
	return true
}

func (l *missingCRLNumber) Execute(c *x509.RevocationList) *lint.LintResult {
	for _, e := range c.Extensions {
		if e.Id.Equal(util.CRLNumberOID) {
			return &lint.LintResult{Status: lint.Pass}
		}
	}

	return &lint.LintResult{
		Status:  lint.Error,
		Details: "This CRL lacks the mandatory CRL Number extension",
	}
}
