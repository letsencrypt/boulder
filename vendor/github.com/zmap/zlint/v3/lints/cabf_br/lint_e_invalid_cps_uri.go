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
 * Contributed by Adriano Santoni <adriano.santoni@staff.aruba.it>
 * of ACTALIS S.p.A. (www.actalis.com).
 */

package cabf_br

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"net/url"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_invalid_cps_uri",
			Description:   "If the CPS URI policyQualifier is present in a certificate, it MUST contain an HTTP or HTTPS URL",
			Citation:      "CABF BR 7.1.2 (several subsections thereof)",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_2_0_0_Date,
		},
		Lint: NewInvalidCPSUri,
	})
}

type invalidCPSUri struct{}

func NewInvalidCPSUri() lint.LintInterface {
	return &invalidCPSUri{}
}

func (l *invalidCPSUri) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.CertPolicyOID)
}

func isValidHttpOrHttpsURL(input string) bool {
	parsedURL, err := url.Parse(input)
	if err != nil {
		return false
	}

	scheme := parsedURL.Scheme
	return scheme == "http" || scheme == "https"
}

func (l *invalidCPSUri) Execute(c *x509.Certificate) *lint.LintResult {
	// There should normally be just one CPS URI, but one never knows...
	for _, pol := range c.CPSuri {
		for _, uri := range pol {
			if !isValidHttpOrHttpsURL(uri) {
				return &lint.LintResult{Status: lint.Error}
			}
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
