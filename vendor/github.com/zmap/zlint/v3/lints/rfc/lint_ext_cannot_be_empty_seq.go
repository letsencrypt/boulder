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

package rfc

import (
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"fmt"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_ext_cannot_be_empty_sequence",
			Description:   "Extensions whose value is SEQUENCE SIZE (1..MAX) OF must have at least 1 element",
			Citation:      "All of RFC 5280",
			Source:        lint.RFC5280,
			EffectiveDate: util.RFC2459Date,
		},
		Lint: NewExtCannotBeEmptySequence,
	})
}

type ExtCannotBeEmptySequence struct{}

func NewExtCannotBeEmptySequence() lint.LintInterface {
	return &ExtCannotBeEmptySequence{}
}

/*
 * According to RFC 5280, the value of all these extensions has an
 * ASN.1 syntax "SEQUENCE SIZE (1..MAX) OF" something, which means
 * a SEQUENCE containing at least one element.
 */
var targetExtensionsMap = map[string]string{
	util.CertPolicyOID.String():           "CertificatePolicies",
	util.PolicyMapOID.String():            "PolicyMappings",
	util.SubjectAlternateNameOID.String(): "SubjectAlternativeNames",
	util.IssuerAlternateNameOID.String():  "IssuerAlternativeNames",
	util.SubjectDirAttrOID.String():       "SubjectDirectoryAttributes",
	util.EkuSynOid.String():               "ExtendedKeyUsage",
	util.CrlDistOID.String():              "CRLDistributionPoints",
	util.AiaOID.String():                  "AuthorityInformationAccess",
	util.SubjectInfoAccessOID.String():    "SubjectInformationAccess",
	util.FreshCRLOID.String():             "FreshestCRL",
}

func (l *ExtCannotBeEmptySequence) CheckApplies(c *x509.Certificate) bool {
	return true
}

func (l *ExtCannotBeEmptySequence) Execute(c *x509.Certificate) *lint.LintResult {

	SequenceOfSomething := []asn1.RawValue{}

	for extOid := range targetExtensionsMap {
		if ext, found := c.ExtensionsMap[extOid]; found {
			_, err := asn1.Unmarshal(ext.Value, &SequenceOfSomething)
			if err != nil {
				return &lint.LintResult{
					Status: lint.Fatal,
					Details: fmt.Sprintf("Cannot parse the %s extension: %v",
						targetExtensionsMap[extOid], err),
				}
			}
			if len(SequenceOfSomething) == 0 {
				return &lint.LintResult{
					Status: lint.Error,
					Details: fmt.Sprintf("The %s extension, if present, MUST contain at least 1 element",
						targetExtensionsMap[extOid]),
				}
			}
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
