package cabf_cs_br

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

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type csSubjectOrgRequired struct{}

/************************************************
CSBRs: 7.1.4.2.3, 7.1.4.2.4
Certificate Field: subject:organizationName (OID 2.5.4.10)
Required/Optional: Required

7.1.4.2.3 (Non-EV Code Signing Certificates):
The subject:organizationName field MUST contain either the Subject's name or DBA as verified
under BR Section 3.2. The CA MAY include information in this field that differs slightly from
the verified name, such as common variations or abbreviations, provided that the CA documents
the difference and any abbreviations used are locally accepted abbreviations; e.g., if the
official record shows "Company Name Incorporated", the CA MAY use "Company Name Inc." or
"Company Name". Because subject name attributes for individuals (e.g. subject:givenName
(2.5.4.42) and subject:surname (2.5.4.4)) are not broadly supported by application software,
the CA MAY use the subject:organizationName field to convey a natural person Subject's name or
DBA. The CA MUST have a documented process for verifying that the information included in the
subject:organizationName field is not misleading to a Relying Party.

7.1.4.2.4 (EV Code Signing Certificates):
This field MUST contain the Subject's full legal organization name as listed in the official
records of the Incorporating or Registration Agency in the Subject's Jurisdiction of
Incorporation or Registration or as otherwise verified by the CA as provided herein. A CA MAY
abbreviate the organization prefixes or suffixes in the organization name, e.g., if the
official record shows "Company Name Incorporated" the CA MAY include "Company Name, Inc."
When abbreviating a Subject's full legal name as allowed by this subsection, the CA MUST use
abbreviations that are not misleading in the Jurisdiction of Incorporation or Registration.
In addition, an assumed name or DBA name used by the Subject MAY be included at the beginning
of this field, provided that it is followed by the full legal organization name in parenthesis.
If the combination of names or the organization name by itself exceeds 64 characters, the CA
MAY abbreviate parts of the organization name, and/or omit non-material words in the
organization name in such a way that the text in this field does not exceed the 64-character
limit; provided that the CA checks this field in accordance with the High Risk Certificate
Request requirements of Section 4.2.1 and a Relying Party will not be misled into thinking
that they are dealing with a different organization. In cases where this is not possible, the
CA MUST NOT issue the EV Code Signing Certificate.
************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cs_requires_org",
			Description:   "Code Signing certificates MUST include organizationName in the subject field",
			Citation:      "CSBRs: 7.1.4.2.3, 7.1.4.2.4", // Applies to both EV and non-EV CS certs
			Source:        lint.CABFCSBaselineRequirements,
			EffectiveDate: util.CABF_CS_BRs_1_2_Date,
		},
		Lint: NewCsSubjectOrgRequired,
	})
}

func NewCsSubjectOrgRequired() lint.LintInterface {
	return &csSubjectOrgRequired{}
}

func (l *csSubjectOrgRequired) CheckApplies(cert *x509.Certificate) bool {
	return util.IsSubscriberCert(cert)
}

func (l *csSubjectOrgRequired) Execute(cert *x509.Certificate) *lint.LintResult {
	if len(cert.Subject.Organization) > 0 {
		return &lint.LintResult{Status: lint.Pass}
	}

	return &lint.LintResult{Status: lint.Error, Details: "Code Signing certificate is missing required organizationName in subject."}
}
