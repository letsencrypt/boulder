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

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type bRAIAAccessMethodAllowed struct{}

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

Each AccessDescription MUST only contain a permitted accessMethod, as detailed below,
and each accessLocation MUST be encoded as the specified GeneralName type.

This lint checks that only the id-ad-ocsp or id-ad-caIssuers accessMethod is present
and that the value is a uniformResourceIdentifier GeneralName.

GeneralName ::= CHOICE {
     otherName                 [0]  AnotherName,
     rfc822Name                [1]  IA5String,
     dNSName                   [2]  IA5String,
     x400Address               [3]  ORAddress,
     directoryName             [4]  Name,
     ediPartyName              [5]  EDIPartyName,
     uniformResourceIdentifier [6]  IA5String,
     iPAddress                 [7]  OCTET STRING,
     registeredID              [8]  OBJECT IDENTIFIER }
*************************************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_aia_must_contain_permitted_access_method",
			Description:   "The AIA must contain only the id-ad-ocsp or id-ad-caIssuers accessMethod. Others are not allowed. Also, each accessLocation MUST be encoded as uniformResourceIdentifier GeneralName.",
			Citation:      "BRs: 7.1.2.7.7",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.SC62EffectiveDate,
		},
		Lint: NewBRAIAAccessMethodAllowed,
	})
}

func NewBRAIAAccessMethodAllowed() lint.LintInterface {
	return &bRAIAAccessMethodAllowed{}
}

func (l *bRAIAAccessMethodAllowed) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.IsExtInCert(c, util.AiaOID)
}

func (l *bRAIAAccessMethodAllowed) Execute(c *x509.Certificate) *lint.LintResult {

	// see x509.go
	for _, ext := range c.Extensions {
		if ext.Id.Equal(util.AiaOID) {
			var aia []authorityInfoAccess
			_, err := asn1.Unmarshal(ext.Value, &aia)
			if err != nil {
				return &lint.LintResult{Status: lint.Fatal}
			}
			for _, v := range aia {
				if v.Location.Tag != 6 {
					return &lint.LintResult{Status: lint.Error, Details: fmt.Sprintf("Certificate has an invalid GeneralName with tag %d in an accessLocation.", v.Location.Tag)}
				}

				if !(v.Method.Equal(idAdCaIssuers) || v.Method.Equal(idAdOCSP)) {
					return &lint.LintResult{Status: lint.Error, Details: fmt.Sprintf("Certificate has an invalid accessMethod with OID %s.", v.Method)}
				}
			}
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}

type authorityInfoAccess struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

var (
	idAdOCSP      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	idAdCaIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)
