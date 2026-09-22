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

package rfc

import (
	"fmt"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/*
 * The thisUpdate field in a CRL indicates the time at which the CRL was issued.
 * For each entry in the revokedCertificates list within the CRL, there is a
 * revocationDate field. This revocationDate signifies when the certificate was revoked.
 * Logically, a certificate cannot be listed as revoked on a CRL with a revocationDate
 * that is after the thisUpdate of that CRL, because thisUpdate marks the point
 * in time that the information in the CRL is considered valid. If a revocation
 * happened after the CRL was issued, it would appear on a subsequent CRL.
 */

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_crl_revocation_time_after_this_update",
			Description:   "All revocation times for revoked certificates must be on or before the thisUpdate field of the CRL.",
			Citation:      "RFC 5280: Section 5.1.2.4 & 5.1.2.6",
			Source:        lint.RFC5280,
			EffectiveDate: util.RFC5280Date,
		},
		Lint: func() lint.RevocationListLintInterface { return &revocationTimeNotAfterThisUpdate{} },
	})
}

type revocationTimeNotAfterThisUpdate struct{}

// CheckApplies returns true if the CRL has any revoked certificates.
func (l *revocationTimeNotAfterThisUpdate) CheckApplies(c *x509.RevocationList) bool {
	return len(c.RevokedCertificates) > 0
}

// Execute checks that for each revoked certificate, the revocation time is not after the CRL's thisUpdate time.
func (l *revocationTimeNotAfterThisUpdate) Execute(c *x509.RevocationList) *lint.LintResult {
	for _, rc := range c.RevokedCertificates {
		if rc.RevocationTime.After(c.ThisUpdate) {
			return &lint.LintResult{
				Status: lint.Error,
				Details: fmt.Sprintf("revoked certificate with serial number %x has a revocation time (%s) after the CRL's thisUpdate time (%s)",
					rc.SerialNumber, rc.RevocationTime.Format(time.RFC3339), c.ThisUpdate.Format(time.RFC3339)),
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
