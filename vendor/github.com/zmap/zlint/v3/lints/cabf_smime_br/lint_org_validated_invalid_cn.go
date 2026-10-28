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

package cabf_smime_br

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"net/mail"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_org_validated_invalid_cn",
			Description:   "In OV S/MIME certs, the Subject CN must either contain an email address or match organizatioName",
			Citation:      "CABF SMIME BRs §7.1.4.2.2",
			Source:        lint.CABFSMIMEBaselineRequirements,
			EffectiveDate: util.CABF_SMIME_BRs_1_0_0_Date,
		},
		Lint: NewOrgValidatedInvalidCN,
	})
}

type OrgValidatedInvalidCN struct{}

func NewOrgValidatedInvalidCN() lint.LintInterface {
	return &OrgValidatedInvalidCN{}
}

func (l *OrgValidatedInvalidCN) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.IsOrganizationValidatedCertificate(c) && c.Subject.CommonName != ""
}

func isEmail(s string) bool {
	addr, err := mail.ParseAddress(s)
	if err != nil {
		return false
	}
	return addr.Address == s
}

func (l *OrgValidatedInvalidCN) Execute(c *x509.Certificate) *lint.LintResult {

	if isEmail(c.Subject.CommonName) ||
		(len(c.Subject.Organization) > 0 && c.Subject.CommonName == c.Subject.Organization[0]) {
		return &lint.LintResult{Status: lint.Pass}
	}

	return &lint.LintResult{
		Status:  lint.Error,
		Details: "In OV S/MIME certs, the Subject CN must either contain an email address or match organizatioName",
	}
}
