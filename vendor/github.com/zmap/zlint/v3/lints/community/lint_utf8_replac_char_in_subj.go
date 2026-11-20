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

package community

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"encoding/asn1"
	"strings"
	"unicode/utf8"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_utf8_replacement_char_in_subject",
			Description:   "Detects the UTF8 Replacement Character anywhere in the Subject field",
			Citation:      "Do not know what to insert here",
			Source:        lint.Community,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewUTF8ReplacementCharInSubject,
	})
}

type attributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

type UTF8ReplacementCharInSubject struct{}

func NewUTF8ReplacementCharInSubject() lint.LintInterface {
	return &UTF8ReplacementCharInSubject{}
}

func (l *UTF8ReplacementCharInSubject) CheckApplies(c *x509.Certificate) bool {
	return true
}

func getAttribName(oidStr string) string {
	attribNames := map[string]string{
		"0.9.2342.19200300.100.1.25": "subject:domainComponent",
		"1.2.840.113549.1.9.1":       "subject:emailAddress",
		"1.3.6.1.4.1.311.60.2.1.1":   "subject:jurisdictionLocality",
		"1.3.6.1.4.1.311.60.2.1.2":   "subject:jurisdictionProvince",
		"1.3.6.1.4.1.311.60.2.1.3":   "subject:jurisdictionCountry",
		"2.5.4.3":                    "subject:commonName",
		"2.5.4.4":                    "subject:surname",
		"2.5.4.5":                    "subject:serialNumber",
		"2.5.4.6":                    "subject:countryName",
		"2.5.4.7":                    "subject:localityName",
		"2.5.4.8":                    "subject:stateOrProvinceName",
		"2.5.4.9":                    "subject:streetAddress",
		"2.5.4.10":                   "subject:organizationName",
		"2.5.4.11":                   "subject:organizationalUnitName",
		"2.5.4.12":                   "subject:title",
		"2.5.4.17":                   "subject:postalCode",
		"2.5.4.42":                   "subject:givenName",
		"2.5.4.65":                   "subject:pseudonym",
		"2.5.4.97":                   "subject:organizationIdentifier",
	}

	name, found := attribNames[oidStr]
	if found {
		return name
	}
	return "Subject attribute with OID " + oidStr
}

func (l *UTF8ReplacementCharInSubject) Execute(c *x509.Certificate) *lint.LintResult {

	var rdnSeq []asn1.RawValue // RDNSequence ::= SEQUENCE OF RDN
	if _, err := asn1.Unmarshal(c.RawSubject, &rdnSeq); err != nil {
		return &lint.LintResult{Status: lint.Fatal, Details: err.Error()}
	}

	for _, rdn := range rdnSeq {
		var atvs []attributeTypeAndValue // RDN ::= SET OF AttributeTypeAndValue
		if _, err := asn1.UnmarshalWithParams(rdn.FullBytes, &atvs, "set"); err != nil {
			return &lint.LintResult{Status: lint.Fatal, Details: err.Error()}
		}
		for _, atv := range atvs {
			if atv.Value.Tag == asn1.TagUTF8String { // tag 12 (0x0C)
				str := string(atv.Value.Bytes)
				if strings.ContainsRune(str, utf8.RuneError) {
					return &lint.LintResult{
						Status: lint.Error,
						Details: "UTF8 Replacement Character detected in " +
							getAttribName(atv.Type.String()),
					}
				}
			}
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
