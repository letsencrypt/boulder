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

package etsi

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

// psd2OrgIdFormatRegex, psd2OrgIdCheckApplies, and psd2OrgIdFormatViolation
// are shared by both e_qcstatem_psd2_orgid_format (this file) and
// w_qcstatem_psd2_orgid_format — they check the exact same condition, only
// severity and the requirement-strength wording differ, so the check logic
// itself is factored out here rather than duplicated. Unexported: both
// callers are in this package, so there's no need to promote this to
// util unless a third consumer outside package etsi shows up. Only the
// country-code capture group is ever read, so the other two groups are
// non-capturing.
var psd2OrgIdFormatRegex = regexp.MustCompile(`^PSD([A-Z]{2})-(?:[A-Z]{2,8})-(?:.+)$`)

type qcStatemPsd2OrgIdFormatShall struct{}

// ETSI TS 119 495 V1.1.2 (2018-07) through V1.4.1 (2019-11), Section 5.2.1:
//
//	GEN-5.2.1-3: The organizationIdentifier attribute shall contain
//	information using the following structure in the presented order:
//	"PSD" as 3 character legal person identity type reference; 2 character
//	ISO 3166 country code representing the NCA country; hyphen-minus "-";
//	2-8 character NCA identifier (A-Z uppercase only, no separator); and
//	hyphen-minus "-"; and PSP identifier (authorization number as
//	specified by the NCA). There are no restrictions on the characters
//	used [for the PSP identifier].
//
// This clause was downgraded from "shall" to "should" in V1.5.1
// (2021-04) onward — this lint only covers the "shall" era. See
// w_qcstatem_psd2_orgid_format for the "should" era that follows it.
func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:            "e_qcstatem_psd2_orgid_format",
			Description:     "Checks that a PSD2 certificate's subject:organizationIdentifier, when it starts with 'PSD', matches the required PSD<country>-<NCAid>-<PSPid> structure",
			Citation:        "ETSI TS 119 495 V1.1.2 (2018-07) - V1.4.1 (2019-11), Section 5.2.1, GEN-5.2.1-3",
			Source:          lint.EtsiEsi,
			EffectiveDate:   util.EtsiTs119495_V1_1_2_Date,
			IneffectiveDate: util.EtsiTs119495_V1_5_1_Date,
		},
		Lint: NewQcStatemPsd2OrgIdFormatShall,
	})
}

// psd2OrgIdCheckApplies checks the cheap Subject-DN conditions before the
// qcStatements extension is parsed, so certificates that don't carry a
// "PSD"-prefixed organizationIdentifier (the common case even among
// QCerts) skip the ASN.1 unmarshal entirely.
//
// Unlike the other PSD2 lints, the Execute methods that rely on this
// deliberately do not defer on GetErrorInfo(). The subject matter here is
// the Subject DN, which is parsed independently of the qcStatements
// extension; a garbled QCStatement neither makes OrganizationIDs unsafe
// to read nor makes the org-id format requirement inapplicable. (Note
// ParseQcStatem reports IsPresent() for any OID when the outer SEQUENCE
// fails to parse, so a "PSD"-prefixed org-id is what actually establishes
// PSD2 applicability here.)
func psd2OrgIdCheckApplies(c *x509.Certificate) bool {
	if len(c.Subject.OrganizationIDs) == 0 || !strings.HasPrefix(c.Subject.OrganizationIDs[0], "PSD") {
		return false
	}
	if !util.IsExtInCert(c, util.QcStateOid) {
		return false
	}
	return util.ParseQcStatem(util.GetExtFromCert(c, util.QcStateOid).Value, util.IdEtsiPsd2Statem).IsPresent()
}

// psd2OrgIdFormatViolation returns a non-empty Details message if orgId
// violates the PSD<country>-<NCAid>-<PSPid> structure, or "" if it's
// valid. requirementWord ("required"/"recommended") reflects the calling
// lint's own era — GEN-5.2.1-3 was "shall" through V1.4.1 and "should"
// from V1.5.1 onward.
func psd2OrgIdFormatViolation(orgId string, requirementWord string) string {
	m := psd2OrgIdFormatRegex.FindStringSubmatch(orgId)
	if m == nil {
		return fmt.Sprintf(
			"subject:organizationIdentifier %q does not match the %s PSD<country>-<NCAid>-<PSPid> structure", orgId, requirementWord)
	}
	if !util.IsISOCountryCode(m[1]) {
		return fmt.Sprintf(
			"subject:organizationIdentifier %q has a country code that is not an assigned ISO 3166-1 country", orgId)
	}
	return ""
}

func NewQcStatemPsd2OrgIdFormatShall() lint.LintInterface {
	return &qcStatemPsd2OrgIdFormatShall{}
}

func (l *qcStatemPsd2OrgIdFormatShall) CheckApplies(c *x509.Certificate) bool {
	return psd2OrgIdCheckApplies(c)
}

// See psd2OrgIdCheckApplies for why this does not defer on GetErrorInfo().
func (l *qcStatemPsd2OrgIdFormatShall) Execute(c *x509.Certificate) *lint.LintResult {
	orgId := c.Subject.OrganizationIDs[0]
	if msg := psd2OrgIdFormatViolation(orgId, "required"); msg != "" {
		return &lint.LintResult{Status: lint.Error, Details: msg}
	}
	return &lint.LintResult{Status: lint.Pass}
}
