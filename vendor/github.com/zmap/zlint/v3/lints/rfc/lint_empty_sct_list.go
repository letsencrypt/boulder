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

package rfc

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"encoding/asn1"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_empty_sct_list",
			Description:   "At least one SCT MUST be included in the SignedCertificateTimestampList extension",
			Citation:      "RFC 6962 section 3.3",
			Source:        lint.RFC6962,
			EffectiveDate: util.RFC6962Date,
		},
		Lint: NewEmptySCTList,
	})
}

type emptySCTList struct{}

func NewEmptySCTList() lint.LintInterface {
	return &emptySCTList{}
}

// CheckApplies returns true for any subscriber certificates that are not precertificates
// (i.e. that do not have the CT poison extension defined in RFC 6962)
func (l *emptySCTList) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && !util.IsExtInCert(c, util.CtPoisonOID)
}

func (l *emptySCTList) Execute(c *x509.Certificate) *lint.LintResult {

	var sctListExtValue []byte

	for _, e := range c.Extensions {
		if e.Id.Equal(util.TimestampOID) {
			sctListExtValue = e.Value
			break
		}
	}

	// SCT extension not found, so there is nothing to check
	if sctListExtValue == nil {
		return &lint.LintResult{Status: lint.Pass}
	}

	var octetString []byte

	_, err := asn1.Unmarshal(sctListExtValue, &octetString)
	if err != nil {
		// This will probably never happen, as at this point the extension has already been parsed by an upper Zlint layer
		return &lint.LintResult{
			Status:  lint.Fatal,
			Details: "Error decoding the SignedCertificateTimestampList extension",
		}
	}

	// Per RFC 5246, the SCT list must begin with a two-bytes length field
	if len(octetString) < 2 {
		// This will probably never happen, as at this point the extension has already been parsed by an upper Zlint layer
		return &lint.LintResult{
			Status:  lint.Fatal,
			Details: "Invalid SCT list encoding (missing length field)",
		}
	}

	// If the SCT list length (first two bytes) is zero, then it's an invalid SCT list per RFC 6962
	if octetString[0] == 0 && octetString[1] == 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "At least one SCT MUST be included in the SignedCertificateTimestampList extension",
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
