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

package cabf_smime_br

import (
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/*************************************************************************

7.1.4.2.3 Subject DN attributes for mailbox?validated profile:
|Attribute               | Legacy     | Multipurpose| Strict
|commonName              | MAY        | MAY        	| MAY
|organizationName        | SHALL NOT  | SHALL NOT  	| SHALL NOT
|organizationalUnitName  | SHALL NOT  | SHALL NOT  	| SHALL NOT
|organizationIdentifier  | SHALL NOT  | SHALL NOT  	| SHALL NOT
|givenName               | SHALL NOT  | SHALL NOT  	| SHALL NOT
|surname                 | SHALL NOT  | SHALL NOT  	| SHALL NOT
|pseudonym               | SHALL NOT  | SHALL NOT  	| SHALL NOT
|serialNumber            | MAY        | MAY        	| MAY
|emailAddress            | MAY        | MAY        	| MAY
|title                   | SHALL NOT  | SHALL NOT  	| SHALL NOT
|streetAddress           | SHALL NOT  | SHALL NOT  	| SHALL NOT
|localityName            | SHALL NOT  | SHALL NOT  	| SHALL NOT
|stateOrProvinceName     | SHALL NOT  | SHALL NOT  	| SHALL NOT
|postalCode              | SHALL NOT  | SHALL NOT  	| SHALL NOT
|countryName             | SHALL NOT  | SHALL NOT  	| SHALL NOT
|Other                   | SHALL NOT  | SHALL NOT  	| SHALL NOT

*************************************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_mailbox_validated_allowed_subjectdn_attributes",
			Description:   "Only certain Subject DN attributes are permitted to be present in mailbox-validated certificates.",
			Citation:      "S/MIME BRs: 7.1.4.2.3",
			Source:        lint.CABFSMIMEBaselineRequirements,
			EffectiveDate: util.CABF_SMIME_BRs_1_0_0_Date,
		},
		Lint: NewMBVSubjectAttributes,
	})
}

type mbvSubjectAttributes struct{}

func NewMBVSubjectAttributes() lint.LintInterface {
	return &mbvSubjectAttributes{}
}

func (l *mbvSubjectAttributes) CheckApplies(c *x509.Certificate) bool {
	return util.IsMailboxValidatedCertificate(c)
}

func (l *mbvSubjectAttributes) Execute(c *x509.Certificate) *lint.LintResult {
	rdnSequence := util.RawRDNSequence{}
	rest, err := asn1.Unmarshal(c.RawSubject, &rdnSequence)
	if err != nil {
		return &lint.LintResult{Status: lint.Fatal}
	}
	if len(rest) > 0 {
		return &lint.LintResult{Status: lint.Fatal}
	}

	notAllowedAttributeFound := false
	for _, attrTypeAndValueSet := range rdnSequence {
		for _, attrTypeAndValue := range attrTypeAndValueSet {
			if !attrTypeAndValue.Type.Equal(util.CommonNameOID) && !attrTypeAndValue.Type.Equal(util.SerialOID) && !attrTypeAndValue.Type.Equal(util.EmailAddressOID) {
				notAllowedAttributeFound = true
			}
		}
	}

	if notAllowedAttributeFound {
		return &lint.LintResult{Status: lint.Error}
	}
	return &lint.LintResult{Status: lint.Pass}
}
