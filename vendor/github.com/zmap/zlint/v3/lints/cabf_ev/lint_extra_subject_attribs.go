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

package cabf_ev

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_ev_extra_subject_attribs",
			Description:   "CAs SHALL NOT include any Subject Distinguished Name attributes except as specified...",
			Citation:      "EVGs §7.1.4.2.9",
			Source:        lint.CABFEVGuidelines,
			EffectiveDate: util.SC16EffectiveDate,
		},
		Lint: NewExtraSubjectAttribs,
	})
}

type extraSubjectAttribs struct{}

func NewExtraSubjectAttribs() lint.LintInterface {
	return &extraSubjectAttribs{}
}

func (l *extraSubjectAttribs) CheckApplies(c *x509.Certificate) bool {
	return util.IsEV(c.PolicyIdentifiers) && util.IsSubscriberCert(c)
}

var allowedAttribs = map[string]bool{
	"1.3.6.1.4.1.311.60.2.1.1": true, // joiLocalityName
	"1.3.6.1.4.1.311.60.2.1.2": true, // joiStateOrProvinceName
	"1.3.6.1.4.1.311.60.2.1.3": true, // joiCountryName
	"2.5.4.3":                  true, // commonName
	"2.5.4.5":                  true, // serialNumber
	"2.5.4.6":                  true, // countryName
	"2.5.4.7":                  true, // localityName
	"2.5.4.8":                  true, // stateOrProvinceName
	"2.5.4.9":                  true, // streetAddress
	"2.5.4.10":                 true, // organizationName
	/*
	 * We also include the OU attribute here, even though it is now banned, because this lint
	 * deals with a more general requirement that came into force long before the OU ban,
	 * and there is already another lint that deals with the OU attribute specifically.
	 */
	"2.5.4.11": true, // organizationUnitName
	"2.5.4.15": true, // businessCategory
	"2.5.4.17": true, // postalCode
	/*
	 * The organizationIdentifier attribute is only permitted starting from 21-may-2019 (EVGL 1.7.0),
	 * which is slightly after SC16 came into force, however any certificates that contain this
	 * attribute and were issued before that date have long since expired, so it makes no difference.
	 */
	"2.5.4.97": true, // organizationIdentifier
}

func (l *extraSubjectAttribs) Execute(c *x509.Certificate) *lint.LintResult {

	var rdnSequence pkix.RDNSequence
	_, err := asn1.Unmarshal(c.RawSubject, &rdnSequence)
	if err != nil {
		return &lint.LintResult{Status: lint.Fatal}
	}

	for _, rdn := range rdnSequence {
		for _, atv := range rdn {
			if !allowedAttribs[atv.Type.String()] {
				return &lint.LintResult{
					Status:  lint.Error,
					Details: fmt.Sprintf("Subject attribute %s is not allowed in EV certificates", atv.Type.String()),
				}
			}
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
