package community

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
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type brIANBareWildcard struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_ian_bare_wildcard",
			Description:   "A wildcard MUST be accompanied by other data to its right (Only checks IANDNSNames)",
			Citation:      "awslabs certlint",
			Source:        lint.Community,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewBrIANBareWildcard,
	})
}

func NewBrIANBareWildcard() lint.LintInterface {
	return &brIANBareWildcard{}
}

func (l *brIANBareWildcard) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.IssuerAlternateNameOID)
}

func (l *brIANBareWildcard) Execute(c *x509.Certificate) *lint.LintResult {
	for _, dns := range c.IANDNSNames {
		if strings.HasSuffix(dns, "*") {
			return &lint.LintResult{Status: lint.Error}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
