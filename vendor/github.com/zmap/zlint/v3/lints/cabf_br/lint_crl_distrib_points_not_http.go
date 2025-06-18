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

	"strings"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_crl_distrib_points_not_http",
			Description:   "The scheme of each CRL Distribution Point MUST be 'http'",
			Citation:      "CABF BRs §7.1.2.11.2",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_2_0_0_Date,
		},
		Lint: NewCrlDistribPointsNotHTTP,
	})
}

type crlDistribPointsNotHTTP struct{}

func NewCrlDistribPointsNotHTTP() lint.LintInterface {
	return &crlDistribPointsNotHTTP{}
}

func (l *crlDistribPointsNotHTTP) CheckApplies(c *x509.Certificate) bool {
	return len(c.CRLDistributionPoints) > 0
}

func (l *crlDistribPointsNotHTTP) Execute(c *x509.Certificate) *lint.LintResult {
	for _, dp := range c.CRLDistributionPoints {
		if !strings.HasPrefix(dp, "http:") {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "Certificate contains a non-HTTP CRL distribution point",
			}
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
