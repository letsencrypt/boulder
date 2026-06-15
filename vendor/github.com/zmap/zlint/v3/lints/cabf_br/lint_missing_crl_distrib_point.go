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

package cabf_br

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"time"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_missing_crl_distrib_point",
			Description:   "Checks for the CDP extension in non-Short-lived Subscriber Certificates lacking an OCSP pointer",
			Citation:      "CABF BRs section 7.1.2.11.2 (CRL Distribution Points)",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.SC63EffectiveDate,
		},
		Lint: NewMissingCRLDistribPoint,
	})
}

type MissingCRLDistribPoint struct{}

func NewMissingCRLDistribPoint() lint.LintInterface {
	return &MissingCRLDistribPoint{}
}

func (l *MissingCRLDistribPoint) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && !IsShortLivedCert(c)
}

func (l *MissingCRLDistribPoint) Execute(c *x509.Certificate) *lint.LintResult {

	if len(c.CRLDistributionPoints) == 0 && len(c.OCSPServer) == 0 {
		return &lint.LintResult{
			Status: lint.Error,
			Details: "The CRLDistributionPoints extension MUST be present in " +
				"non-Short-Lived certificates lacking an OCSP URI",
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}

// Based on CABF BRs §1.6.1 (Definitions)
func IsShortLivedCert(c *x509.Certificate) bool {
	thresholdDate := time.Date(2026, time.March, 15, 0, 0, 0, 0, time.UTC)
	tenDaysInSeconds := 864000
	sevenDaysInSeconds := 604800

	if c.NotBefore.Before(thresholdDate) {
		return c.ValidityPeriod <= tenDaysInSeconds
	} else {
		return c.ValidityPeriod <= sevenDaysInSeconds
	}
}
