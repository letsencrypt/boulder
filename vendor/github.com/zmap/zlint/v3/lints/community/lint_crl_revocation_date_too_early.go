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
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/*
 * This lint checks that the revocation time for a revoked certificate is not too early.
 * This is particularly useful when a programming language (e.g., Go) uses a default
 * zero-value (0001-01-01T00:00:00Z) for a time if not set explicitly.
 * For all intents and purposes, the revocation time for a revoked certificate should not be
 * before the RFC 2459 (Internet X.509 Public Key Infrastructure Certificate and CRL Profile),
 * which first introduced the CRL profile.
 */

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:        "e_crl_revocation_date_too_early",
			Description: "The revocation time of each revoked certificate should not before the publication date of RFC 2459.",
			Source:      lint.Community,
		},
		Lint: func() lint.RevocationListLintInterface { return &revocationDateTooEarly{} },
	})
}

type revocationDateTooEarly struct{}

func (l *revocationDateTooEarly) CheckApplies(c *x509.RevocationList) bool {
	// This check applies to any CRL that has at least one revoked certificate.
	return len(c.RevokedCertificates) > 0
}

func (l *revocationDateTooEarly) Execute(c *x509.RevocationList) *lint.LintResult {
	for _, rc := range c.RevokedCertificates {
		if rc.RevocationTime.Before(util.RFC2459Date) {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: fmt.Sprintf("Revoked certificate with serial number %x has a revocation time (%s) that is before RFC 2459", rc.SerialNumber, rc.RevocationTime.Format(time.RFC3339)),
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
