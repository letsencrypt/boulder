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
			Name:          "e_crl_unique_revoked_certificate",
			Description:   "The CRL must not include duplicate serial numbers in its revoked certificates list.",
			Source:        lint.Community,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewUniqueRevokedCertificate,
	})
}

type uniqueRevokedCertificate struct{}

func NewUniqueRevokedCertificate() lint.RevocationListLintInterface {
	return &uniqueRevokedCertificate{}
}

func (l *uniqueRevokedCertificate) CheckApplies(c *x509.RevocationList) bool {
	return true
}

func (l *uniqueRevokedCertificate) Execute(c *x509.RevocationList) *lint.LintResult {
	serials := make(map[string]bool)
	for _, rc := range c.RevokedCertificates {
		if serials[rc.SerialNumber.String()] {
			return &lint.LintResult{
				Status:  lint.Warn,
				Details: fmt.Sprintf("Revoked certificates list contains duplicate serial number: %x", rc.SerialNumber),
			}
		}
		serials[rc.SerialNumber.String()] = true
	}
	return &lint.LintResult{Status: lint.Pass}
}
