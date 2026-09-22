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
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"slices"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_subj_email_not_in_san",
			Description:   "Certificates with email addresses MUST include them in the SAN extension",
			Citation:      "RFC 5280 Section 4.1.2.6",
			Source:        lint.RFC5280,
			EffectiveDate: util.RFC2459Date,
		},
		Lint: NewSubjEmailAddrNotInSAN,
	})
}

type SubjEmailAddrNotInSAN struct{}

func NewSubjEmailAddrNotInSAN() lint.LintInterface {
	return &SubjEmailAddrNotInSAN{}
}

func (l *SubjEmailAddrNotInSAN) CheckApplies(c *x509.Certificate) bool {
	return len(c.Subject.EmailAddress) > 0
}

func (l *SubjEmailAddrNotInSAN) Execute(c *x509.Certificate) *lint.LintResult {

	for _, emailAddr := range c.Subject.EmailAddress {
		if !slices.Contains(c.EmailAddresses, emailAddr) {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "At least one email address in the Subject does not appear in the SAN",
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
