/*
 * ZLint Copyright 2026 Regents of the University of Michigan
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
	"regexp"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name: "n_suspicious_chars_in_address",
			Description: "Checks whether Subject:localityName or Subject:stateOrProvinceName contain " +
				"characters that suggest the attribute holds more than one concatenated address component",
			Citation: "ZLint community heuristic, informed by real-world incident reports: a comma, colon, " +
				"equals sign, quotation mark, or parenthesis inside localityName or stateOrProvinceName is a " +
				"strong sign that the attribute improperly concatenates multiple address components (e.g. a " +
				"locality plus a street address, or a locality plus a region) rather than naming a single " +
				"locality or region. This is not codified in any formal specification, so this lint is " +
				"informational only and may not indicate an error in every case.",
			Source:        lint.Community,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewSuspiciousCharsInAddress,
	})
}

type SuspiciousCharsInAddress struct{}

func NewSuspiciousCharsInAddress() lint.LintInterface {
	return &SuspiciousCharsInAddress{}
}

func (l *SuspiciousCharsInAddress) CheckApplies(c *x509.Certificate) bool {
	return len(c.Subject.Locality) > 0 || len(c.Subject.Province) > 0
}

var suspiciousCharsInAddressRegexp = regexp.MustCompile(`[,:="()]`)

func containsSuspiciousChars(values []string) bool {
	for _, v := range values {
		if suspiciousCharsInAddressRegexp.MatchString(v) {
			return true
		}
	}
	return false
}

func (l *SuspiciousCharsInAddress) Execute(c *x509.Certificate) *lint.LintResult {
	locSuspicious := containsSuspiciousChars(c.Subject.Locality)
	stateSuspicious := containsSuspiciousChars(c.Subject.Province)

	switch {
	case locSuspicious && stateSuspicious:
		return &lint.LintResult{
			Status:  lint.Notice,
			Details: "Subject:localityName and Subject:stateOrProvinceName both contain suspicious character(s)",
		}
	case locSuspicious:
		return &lint.LintResult{
			Status:  lint.Notice,
			Details: "Subject:localityName contains suspicious character(s)",
		}
	case stateSuspicious:
		return &lint.LintResult{
			Status:  lint.Notice,
			Details: "Subject:stateOrProvinceName contains suspicious character(s)",
		}
	default:
		return &lint.LintResult{Status: lint.Pass}
	}
}
