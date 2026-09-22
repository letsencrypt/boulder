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

	"strings"
)

func init() {

	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_arpa_domain_not_allowed",
			Description:   "CAs SHALL NOT issue Certificates containing Domain Names that end in an IP Reverse Zone Suffix",
			Citation:      "CABF TLS BRs section 4.2.2",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABF_SC086_EffectiveDate,
		},
		Lint: NewARPADomainNotAllowed,
	})
}

type ARPADomainNotAllowed struct{}

func NewARPADomainNotAllowed() lint.LintInterface {
	return &ARPADomainNotAllowed{}
}

func (l *ARPADomainNotAllowed) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *ARPADomainNotAllowed) Execute(c *x509.Certificate) *lint.LintResult {

	reverseZoneSuffixV4 := ".in-addr.arpa"
	reverseZoneSuffixV6 := ".ip6.arpa"

	for _, d := range c.DNSNames {
		if strings.HasSuffix(strings.ToLower(d), reverseZoneSuffixV4) ||
			strings.HasSuffix(strings.ToLower(d), reverseZoneSuffixV6) {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "Domain Names that end in an IP Reverse Zone Suffix are not allowed",
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
