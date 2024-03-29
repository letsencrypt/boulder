package cabf_br

/*
 * ZLint Copyright 2023 Regents of the University of Michigan
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

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_organizational_unit_name_prohibited",
			Description:   "OrganizationalUnitName is prohibited if...the certificate was issued on or after September 1, 2022",
			Citation:      "BRs: 7.1.4.2.2-i",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_OU_Prohibited_Date,
		},
		Lint: NewOrganizationalUnitNameProhibited,
	})
}

type OrganizationalUnitNameProhibited struct{}

func NewOrganizationalUnitNameProhibited() lint.LintInterface {
	return &OrganizationalUnitNameProhibited{}
}

func (l *OrganizationalUnitNameProhibited) CheckApplies(c *x509.Certificate) bool {
	return !c.IsCA
}

func (l *OrganizationalUnitNameProhibited) Execute(c *x509.Certificate) *lint.LintResult {
	if c.Subject.OrganizationalUnit != nil {
		return &lint.LintResult{Status: lint.Error}
	}

	return &lint.LintResult{Status: lint.Pass}
}
