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

/*
 * Contributed by Adriano Santoni <asantoni64@gmail.com>
 */

package cabf_br

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_subj_orgunit_in_ca_cert",
			Description:   "The organizationalUnitName MUST NOT be included in Root CA certs or TLS Subordinate CA certs. organizationalUnitName is allowed for cross signed certificates, although not recommended. This lint may be configured to signify that the target is a cross signed certificate.",
			Citation:      "CABF BR §7.1.2.10.2 (CA Certificate Naming)",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_2_0_0_Date,
		},
		Lint: NewSubjectOrgUnitInCACert,
	})
}

type subjectOrgUnitInCACert struct {
	CrossCert bool `comment:"Set this to true if the certificate to be linted is a cross-certificate"`
}

func NewSubjectOrgUnitInCACert() lint.LintInterface {
	return &subjectOrgUnitInCACert{
		CrossCert: false,
	}
}

func (l *subjectOrgUnitInCACert) Configure() interface{} {
	return l
}

func (l *subjectOrgUnitInCACert) CheckApplies(c *x509.Certificate) bool {
	return util.IsCACert(c)
}

func (l *subjectOrgUnitInCACert) Execute(c *x509.Certificate) *lint.LintResult {
	if c.Subject.OrganizationalUnit != nil {
		if !l.CrossCert {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "The OU attribute in the Subject is prohibited in Root and TLS CA certificates",
			}
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
