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

/*
--- Citation History of this Requirement ---
v2.0.0 to v2.1.7: 7.1.2.10.3

--- Version Notes ---
This requirement was baselined at v2.1.7 and is current.

--- Requirements Language ---
BRs: 7.1.2
If the CA asserts compliance with these Baseline Requirements, all certificates that it issues MUST
comply with one of the following certificate profiles

[Each of the CA profiles specifies the authorityInformationAccess extension follows 7.1.2.10.3]

BRs: 7.1.2.10.3
If present, the AuthorityInfoAccessSyntax MUST contain one or moreAccessDescriptions. Each
AccessDescription MUST only contain a permitted accessMethod, as detailed below, and each accessLocation
MUST be encoded as the specified GeneralName type.
+-----------------+-----------+---------------------------+----------+---------+---------------------------+
| Access Method   | OID       | Access Location           | Presence | Maximum | Description               |
+-----------------+-----------+---------------------------+----------+---------+---------------------------+
| id-ad-ocsp      | 1.3.6.1.5 | uniformResourceIdentifier | MAY      | *       | A HTTP URL of the Issuing |
|                 | .5.7.48.1 |                           |          |         | CA’s OCSP responder.      |
+-----------------+-----------+---------------------------+----------+---------+---------------------------+
| id-ad-caIssuers | 1.3.6.1.5 | uniformResourceIdentifier | MAY      | *       | A HTTP URL of the Issuing |
|                 | .5.7.48.2 |                           |          |         | CA’s certificate.         |
+-----------------+-----------+---------------------------+----------+---------+---------------------------+
*/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_ca_aia_non_http_url",
			Description:   "Within the AIA extension of CA certificates, accessLocations must contain HTTP URLs",
			Citation:      "CABF BRs section 7.1.2.10.3 (CA Certificate Authority Information Access)",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.SC62EffectiveDate,
		},
		Lint: NewCAAIANonHTTPURL,
	})
}

type CAAIANonHTTPURL struct{}

func NewCAAIANonHTTPURL() lint.LintInterface {
	return &CAAIANonHTTPURL{}
}

func (l *CAAIANonHTTPURL) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubCA(c) &&
		(len(c.IssuingCertificateURL) > 0 || len(c.OCSPServer) > 0)
}

func (l *CAAIANonHTTPURL) Execute(c *x509.Certificate) *lint.LintResult {
	for _, url := range c.IssuingCertificateURL {
		if !strings.HasPrefix(strings.ToLower(url), "http://") {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "For the 'caIssuers' accessMethod within the AIA extension, accessLocation must contain an HTTP URL",
			}
		}
	}

	for _, url := range c.OCSPServer {
		if !strings.HasPrefix(strings.ToLower(url), "http://") {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "For the 'ocsp' accessMethod within the AIA extension, accessLocation must contain an HTTP URL",
			}
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
