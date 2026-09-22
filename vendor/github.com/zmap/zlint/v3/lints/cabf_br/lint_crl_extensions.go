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
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:        "e_crl_extensions_validity",
			Description: "Checks that only allowed extensions are present in a CRL and that their criticality is set correctly.",
			Citation:    "BRs: 7.2.2",
			Source:      lint.CABFBaselineRequirements,
		},
		Lint: func() lint.RevocationListLintInterface { return &crlExtensions{} },
	})
}

type crlExtensions struct {
	// allowedExtensions maps the OID of an allowed extension to a boolean
	// indicating whether the extension MUST be marked critical.
	allowedExtensions map[string]bool
}

// newCRLExtensions initializes and returns a new crlExtensions lint.
// This function is not called directly but is used by the ZLint framework.
func (l *crlExtensions) Initialize() {
	l.allowedExtensions = map[string]bool{
		util.CRLNumberOID.String():   false, // cRLNumber
		util.AuthkeyOID.String():     false, // authorityKeyIdentifier
		util.IssuingDistOID.String(): true,  // issuingDistributionPoint
	}
}

// CheckApplies returns true for any CRL, as all CRLs must be checked for extension validity.
func (l *crlExtensions) CheckApplies(c *x509.RevocationList) bool {
	return true
}

// isExtensionAllowed checks if a given extension is in the list of allowed or discouraged extensions.
func (l *crlExtensions) isExtensionAllowed(ext pkix.Extension) bool {
	oid := ext.Id.String()
	if _, ok := l.allowedExtensions[oid]; ok {
		return true
	}
	return false
}

// Execute performs the linting checks on the CRL extensions.
func (l *crlExtensions) Execute(c *x509.RevocationList) *lint.LintResult {
	l.Initialize()
	// First, check for any extensions that are explicitly forbidden.
	for _, ext := range c.Extensions {
		if !l.isExtensionAllowed(ext) {
			return &lint.LintResult{
				Status:  lint.Warn,
				Details: fmt.Sprintf("CRL Extension %s is NOT RECOMMENDED", ext.Id),
			}
		}
	}

	// Second, check that the criticality of allowed extensions is correct.
	for _, ext := range c.Extensions {
		oid := ext.Id.String()
		if mustBeCritical, ok := l.allowedExtensions[oid]; ok {
			if ext.Critical != mustBeCritical {
				return &lint.LintResult{
					Status:  lint.Error,
					Details: fmt.Sprintf("CRL extension %s has incorrect criticality; expected %t, got %t", ext.Id, mustBeCritical, ext.Critical),
				}
			}
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
