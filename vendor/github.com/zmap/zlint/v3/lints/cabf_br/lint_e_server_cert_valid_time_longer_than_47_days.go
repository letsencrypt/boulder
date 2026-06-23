/*
 * ZLint Copyright 2025 Regents of the University of Michigan
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

package cabf_br

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type sc081ThirdDate47ServerCertValidityTooLong struct{}

/************************************************************************

CA/B-Forum SC-081 introduces new validity periods for certificates issued on or after

March 15, 2026
March 15, 2027
March 15, 2029

The change in the requirements is described here: https://github.com/cabforum/servercert/pull/553/files

Subscriber Certificates issued on or after 15 March 2026 and before 15 March 2027 SHOULD NOT have a Validity Period greater than 199 days and MUST NOT have a Validity Period greater than 200 days.

Subscriber Certificates issued on or after 15 March 2027 and before 15 March 2029 SHOULD NOT have a Validity Period greater than 99 days and MUST NOT have a Validity Period greater than 100 days.

Subscriber Certificates issued on or after 15 March 2029 SHOULD NOT have a Validity Period greater than 46 days and MUST NOT have a Validity Period greater than 47 days.

| __Certificate issued on or after__ | __Certificate issued before__  | __Maximum Validity Period__  |
| --                                 | --                             | --                           |
|                                    | March 15, 2026                 | 398 days                     |
| March 15, 2026                     | March 15, 2027                 | 200 days                     |
| March 15, 2027                     | March 15, 2029                 | 100 days                     |
| March 15, 2029                     |                                | 47 days                      |

*************************************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_server_cert_valid_time_longer_than_47_days",
			Description:   "TLS server certificates issued on or after on or after March 15, 2029 00:00 GMT/UTC must not have a validity period greater than 47 days",
			Citation:      "https://github.com/cabforum/servercert/pull/553",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABF_SC081_THIRD_MILESTONE,
		},
		Lint: NewSC081ThirdDate47ServerCertValidityTooLong,
	})
}

func NewSC081ThirdDate47ServerCertValidityTooLong() lint.LintInterface {
	return &sc081ThirdDate47ServerCertValidityTooLong{}
}

func (l *sc081ThirdDate47ServerCertValidityTooLong) CheckApplies(c *x509.Certificate) bool {
	return util.IsServerAuthCert(c) && !c.IsCA
}

func (l *sc081ThirdDate47ServerCertValidityTooLong) Execute(c *x509.Certificate) *lint.LintResult {
	if util.GreaterThan(c, 47) {
		return &lint.LintResult{Status: lint.Error, Details: fmt.Sprintf("Certificate is issued on or after March 15, 2029 and has a validity of %.0f days", util.CertificateValidityInDays(c))}
	}
	return &lint.LintResult{Status: lint.Pass}
}
