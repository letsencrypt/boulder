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
	"net/url"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type bRAIACAIssuersHasHTTPOnly struct{}

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

id-ad-caIssuers
1.3.6.1.5.5.7.48.2 uniformResourceIdentifier SHOULD  A HTTP URL of the
Issuing CA’s certificate
*************************************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_aia_ca_issuers_must_have_http_only",
			Description:   "The id-ad-caIssuers accessMethod must contain an HTTP URL of the Issuing CA’s certificate. Other schemes are not allowed.",
			Citation:      "BRs: 7.1.2.7.7",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.SC62EffectiveDate,
		},
		Lint: NewBRAIACAIssuersHasHTTPOnly,
	})
}

func NewBRAIACAIssuersHasHTTPOnly() lint.LintInterface {
	return &bRAIACAIssuersHasHTTPOnly{}
}

func (l *bRAIACAIssuersHasHTTPOnly) CheckApplies(c *x509.Certificate) bool {
	return len(c.IssuingCertificateURL) > 0 && util.IsSubscriberCert(c)
}

func (l *bRAIACAIssuersHasHTTPOnly) Execute(c *x509.Certificate) *lint.LintResult {
	for _, u := range c.IssuingCertificateURL {
		purl, err := url.Parse(u)
		if err != nil {
			return &lint.LintResult{Status: lint.Error, Details: "Could not parse caIssuers in AIA."}
		}
		if purl.Scheme != "http" {
			return &lint.LintResult{Status: lint.Error, Details: fmt.Sprintf("Found scheme %s in caIssuers of AIA, which is not allowed.", purl.Scheme)}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
