package cabf_br

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

import (
	"fmt"
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type bRAIAAccessLocationUnique struct{}

/************************************************************************
7.1.2.7.7 Subscriber Certificate Authority Information Access
The AuthorityInfoAccessSyntax MUST contain one or more AccessDescriptions. Each
AccessDescription MUST only contain a permitted accessMethod, as detailed below, and
each accessLocation MUST be encoded as the specified GeneralName type.
The AuthorityInfoAccessSyntax MAY contain multiple AccessDescriptions with the
same accessMethod, if permitted for that accessMethod. When multiple
AccessDescriptions are present with the same accessMethod, each accessLocation
MUST be unique, and each AccessDescription MUST be ordered in priority for that
accessMethod, with the most‐preferred accessLocation being the first
AccessDescription. No ordering requirements are given for AccessDescriptions that
contain different accessMethods, provided that previous requirement is satisfied.

When multiple AccessDescriptions are present with the same accessMethod,
each accessLocation MUST be unique.
*************************************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_aia_unique_access_locations",
			Description:   "When multiple AccessDescriptions are present with the same accessMethod in the AIA extension, then each accessLocation MUST be unique.",
			Citation:      "BRs: 7.1.2.7.7",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.SC62EffectiveDate,
		},
		Lint: NewBRAIAAccessLocationUnique,
	})
}

func NewBRAIAAccessLocationUnique() lint.LintInterface {
	return &bRAIAAccessLocationUnique{}
}

func (l *bRAIAAccessLocationUnique) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && (len(c.IssuingCertificateURL) > 0 || len(c.OCSPServer) > 0)
}

func (l *bRAIAAccessLocationUnique) Execute(c *x509.Certificate) *lint.LintResult {

	ocspURLs := make([]string, 0)
	for _, url := range c.OCSPServer {
		for _, foundURL := range ocspURLs {
			if strings.EqualFold(url, foundURL) {
				return &lint.LintResult{Status: lint.Error, Details: fmt.Sprintf("accessLocation with URL %s is found more than once in OCSP URLs", url)}
			}
		}
		ocspURLs = append(ocspURLs, url)
	}

	issuingCertificateURLs := make([]string, 0)
	for _, url := range c.IssuingCertificateURL {
		for _, foundURL := range issuingCertificateURLs {
			if strings.EqualFold(url, foundURL) {
				return &lint.LintResult{Status: lint.Error, Details: fmt.Sprintf("accessLocation with URL %s is found more than once in caIssuers URLs", url)}
			}
		}
		issuingCertificateURLs = append(issuingCertificateURLs, url)
	}

	return &lint.LintResult{Status: lint.Pass}
}
