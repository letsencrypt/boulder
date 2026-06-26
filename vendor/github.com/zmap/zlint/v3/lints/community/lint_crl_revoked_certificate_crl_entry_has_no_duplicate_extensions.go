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
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_crl_revoked_certificate_crl_entry_has_no_duplicate_extensions",
			Description:   "The revoked certificate in the CRL must not have duplicate extensions.",
			Source:        lint.Community,
			EffectiveDate: util.ZeroDate,
		},
		Lint: func() lint.RevocationListLintInterface { return &noDuplicatesInCRLEntryExtension{} },
	})
}

type noDuplicatesInCRLEntryExtension struct{}

func (l *noDuplicatesInCRLEntryExtension) CheckApplies(c *x509.RevocationList) bool {
	return true
}

func (l *noDuplicatesInCRLEntryExtension) Execute(c *x509.RevocationList) *lint.LintResult {
	for _, rc := range c.RevokedCertificates {
		crlEntryExtensions := make(map[string]bool)
		for _, ext := range rc.Extensions {
			if crlEntryExtensions[ext.Id.String()] {
				return &lint.LintResult{
					Status:  lint.Error,
					Details: fmt.Sprintf("Revoked certificate %x has a duplicate extension: %s", rc.SerialNumber, ext.Id.String()),
				}
			}
			crlEntryExtensions[ext.Id.String()] = true
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
