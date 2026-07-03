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
)

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:        "e_crl_no_duplicate_extensions",
			Description: "The CRL must not include duplicate extensions.",
			Source:      lint.Community,
		},
		Lint: func() lint.RevocationListLintInterface { return &noDuplicateExtensions{} },
	})
}

type noDuplicateExtensions struct{}

// CheckApplies returns true if the CRL has any extensions to check.
func (l *noDuplicateExtensions) CheckApplies(c *x509.RevocationList) bool {
	return len(c.Extensions) > 0
}

// Execute checks for duplicate extensions within the CRL.
func (l *noDuplicateExtensions) Execute(c *x509.RevocationList) *lint.LintResult {
	extensions := make(map[string]struct{})
	for _, ext := range c.Extensions {
		oid := ext.Id.String()
		if _, ok := extensions[oid]; ok {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "CRL contains duplicate extension " + oid,
			}
		}
		extensions[oid] = struct{}{}
	}
	return &lint.LintResult{Status: lint.Pass}
}
