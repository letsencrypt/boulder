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

package chrome

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"slices"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_client_auth_not_allowed",
			Description:   "Checks that Server certs do not contain clientAuth in the EKU extension",
			Citation:      "Chrome Root Program Policy, Version 1.8, section 1.3.2",
			Source:        lint.ChromeRootStorePolicy,
			EffectiveDate: util.ChromePolicyClientAuthDisallowedDate,
		},
		Lint: NewClientAuthNotAllowed,
	})
}

type ClientAuthNotAllowed struct{}

func NewClientAuthNotAllowed() lint.LintInterface {
	return &ClientAuthNotAllowed{}
}

func (l *ClientAuthNotAllowed) CheckApplies(c *x509.Certificate) bool {
	return util.IsServerAuthCert(c) && util.IsSubscriberCert(c)
}

func (l *ClientAuthNotAllowed) Execute(c *x509.Certificate) *lint.LintResult {

	if slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "The Chrome Root Store Policy prohibits the clientAuth key purpose in the EKU extension",
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
