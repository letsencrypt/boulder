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
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:                    "e_ocsp_cert_cdp_forbidden",
			Description:             "In OCSP certificates, the CDP extension MUST NOT appear",
			Citation:                "CABF TLS BRs §7.1.2.8.2 OCSP Responder Extensions",
			Source:                  lint.CABFBaselineRequirements,
			EffectiveDate:           util.SC62EffectiveDate,
			OverrideFrameworkFilter: true,
		},
		Lint: NewOcspCertCDPForbidden,
	})
}

type OcspCertCDPForbidden struct{}

func NewOcspCertCDPForbidden() lint.LintInterface {
	return &OcspCertCDPForbidden{}
}

func (l *OcspCertCDPForbidden) CheckApplies(c *x509.Certificate) bool {
	return util.HasEKU(c, x509.ExtKeyUsageOcspSigning)
}

func (l *OcspCertCDPForbidden) Execute(c *x509.Certificate) *lint.LintResult {
	if len(c.CRLDistributionPoints) > 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "An OSCP Responder certificate MUST NOT contain the CRLDistributionPoints extension",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
