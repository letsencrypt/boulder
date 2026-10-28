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

package cabf_ev

import (
	"fmt"
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_ev_subject_orgid_ext_mismatch",
			Description:   "If both are present, each component of the cabfOrganizationIdentifier extension MUST match the corresponding component of the subject:organizationIdentifier attribute",
			Citation:      "EVGs: 7.1.2.2 and 7.1.4.2.8",
			Source:        lint.CABFEVGuidelines,
			EffectiveDate: util.CABFEV_2_0_2_Date,
		},
		Lint: NewSubjectOrgIdExtMismatch,
	})
}

type subjectOrgIdExtMismatch struct{}

func NewSubjectOrgIdExtMismatch() lint.LintInterface {
	return &subjectOrgIdExtMismatch{}
}

type orgIdComponents struct {
	Scheme    string
	Country   string
	State     string
	Reference string
}

// Per the Note in EVGs 7.1.4.2.8, Registration References may contain hyphens
// while Registration Scheme identifiers, ISO 3166 country codes and ISO 3166-2
// identifiers may not, so the leftmost hyphen is the separator and every
// remaining hyphen belongs to the Registration Reference. That is why the PSD
// scheme's National Competent Authority identifier (the "NBB" in
// "PSDBE-NBB-1234.567.890") forms part of the Registration Reference rather than
// a component of its own.
func splitSubjectOrgId(orgID string) (orgIdComponents, bool) {
	var parsed orgIdComponents

	sep := strings.Index(orgID, "-")
	if sep < 0 {
		return parsed, false
	}

	// For example if its NTRUS+CA-1234, the schemePortion would be "NTRUS+CA" and the reference would be "1234"
	schemePortion := orgID[:sep]
	parsed.Reference = orgID[sep+1:]
	if parsed.Reference == "" || len(schemePortion) < 5 {
		return parsed, false
	}

	parsed.Scheme = schemePortion[0:3]
	parsed.Country = schemePortion[3:5]

	// If there is a remainder after the country code, it must start with a '+' and is treated as the state/ISO 3166-2 subdivision.
	remainder := schemePortion[5:]
	if remainder == "" {
		return parsed, true
	}
	if !strings.HasPrefix(remainder, "+") {
		return parsed, false
	}

	// The remainder after the country code is the state/ISO 3166-2 subdivision, without the leading '+'.
	parsed.State = remainder[1:]
	if parsed.State == "" {
		return parsed, false
	}

	return parsed, true
}

func (l *subjectOrgIdExtMismatch) CheckApplies(c *x509.Certificate) bool {
	if !util.IsEV(c.PolicyIdentifiers) || len(c.Subject.OrganizationIDs) == 0 {
		return false
	}

	// This lint doesn't deal with the presence or absence of the extension itself. e_ev_organization_id_missing handles the missing extension case.
	if c.CABFOrganizationIdentifier == nil {
		return false
	}
	// A subject attribute without the structure of EVGs 7.1.4.2.8 cannot be
	// decomposed into components to compare against.
	_, ok := splitSubjectOrgId(c.Subject.OrganizationIDs[0])
	return ok
}

func (l *subjectOrgIdExtMismatch) Execute(c *x509.Certificate) *lint.LintResult {
	subjectOrgID := c.Subject.OrganizationIDs[0]
	// CheckApplies has already established that this decomposes cleanly.
	parsed, _ := splitSubjectOrgId(subjectOrgID)
	ext := c.CABFOrganizationIdentifier

	comparisons := []struct {
		field    string
		fromExt  string
		fromSubj string
	}{
		{"registrationSchemeIdentifier", ext.Scheme, parsed.Scheme},
		{"registrationCountry", ext.Country, parsed.Country},
		{"registrationStateOrProvince", ext.State, parsed.State},
		{"registrationReference", ext.Reference, parsed.Reference},
	}

	var mismatches []string
	for _, cmp := range comparisons {
		if cmp.fromExt != cmp.fromSubj {
			mismatches = append(mismatches, fmt.Sprintf("%s is '%s' but the subject attribute has '%s'", cmp.field, cmp.fromExt, cmp.fromSubj))
		}
	}

	if len(mismatches) > 0 {
		return &lint.LintResult{
			Status: lint.Error,
			Details: fmt.Sprintf("cabfOrganizationIdentifier extension is inconsistent with subject:organizationIdentifier '%s': %s",
				subjectOrgID, strings.Join(mismatches, "; ")),
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
