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

/*
 * Contributed by Adriano Santoni <asantoni64@gmail.com>
 */

package cabf_br

import (
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"fmt"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_duplicate_subject_attribs",
			Description:   "Each Name MUST NOT contain more than one instance of a given AttributeTypeAndValue across all RDNs",
			Citation:      "CABF BRs 7.1.4.1",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_2_0_0_Date,
		},
		Lint: NewDuplicateSubjectAttribs,
	})
}

type duplicateSubjectAttribs struct{}

func NewDuplicateSubjectAttribs() lint.LintInterface {
	return &duplicateSubjectAttribs{}
}

func (l *duplicateSubjectAttribs) CheckApplies(c *x509.Certificate) bool {
	return true
}

// The domainComponent and streetAddress attributes are exempt from
// the single-instance requirement; organizationalUnitName would be too,
// if it weren't for the fact that it has been deprecated.

var singleInstanceOIDs = map[string]string{
	"1.3.6.1.4.1.311.60.2.1.1": "jurisdictionLocality",
	"1.3.6.1.4.1.311.60.2.1.2": "jurisdictionStateOrProvince",
	"1.3.6.1.4.1.311.60.2.1.3": "jurisdictionCountry",
	"2.5.4.3":                  "commonName",
	"2.5.4.4":                  "surname",
	"2.5.4.5":                  "serialNumber",
	"2.5.4.6":                  "countryName",
	"2.5.4.7":                  "localityName",
	"2.5.4.8":                  "stateOrProvinceName",
	"2.5.4.10":                 "organizationName",
	"2.5.4.15":                 "businessCategory",
	"2.5.4.42":                 "givenName",
	"2.5.4.97":                 "organizationIdentifier",
}

func (l *duplicateSubjectAttribs) Execute(c *x509.Certificate) *lint.LintResult {

	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(c.RawSubject, &subject); err != nil {
		return &lint.LintResult{Status: lint.Fatal}
	}

	foundOIDs := make(map[string]bool)

	for _, rdn := range subject {
		for _, ava := range rdn {
			oid := fmt.Sprint(ava.Type)
			name, mustBeSingle := singleInstanceOIDs[oid]
			_, alreadySeen := foundOIDs[oid]
			if mustBeSingle && alreadySeen {
				return &lint.LintResult{
					Status:  lint.Error,
					Details: fmt.Sprintf("Multiple instances of '%s' are NOT allowed in the Subject", name),
				}
			}
			foundOIDs[oid] = true
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
