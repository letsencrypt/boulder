package rfc

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

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_crl_has_authority_key_identifier",
			Description:   "The CRL must include Authority Key Identifier extension.",
			Citation:      "RFC5280 §5.2.1",
			Source:        lint.RFC5280,
			EffectiveDate: util.RFC5280Date,
		},
		Lint: func() lint.RevocationListLintInterface { return &crlAuthKeyID{} },
	})
}

type crlAuthKeyID struct{}

func (l *crlAuthKeyID) CheckApplies(_ *x509.RevocationList) bool {
	return true
}

func (l *crlAuthKeyID) Execute(c *x509.RevocationList) *lint.LintResult {
	for _, ext := range c.Extensions {
		if ext.Id.Equal(util.AuthkeyOID) {
			return &lint.LintResult{Status: lint.Pass}
		}
	}
	return &lint.LintResult{Status: lint.Error, Details: "The CRL lacks the mandatory Authority Key Identifier extension."}
}
