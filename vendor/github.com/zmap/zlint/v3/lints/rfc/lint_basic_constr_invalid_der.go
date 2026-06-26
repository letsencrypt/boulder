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
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_basic_constr_invalid_der",
			Description:   "Checks the correct DER encoding of the cA field in the BasicConstraints ext",
			Citation:      "RFC 3280 §4.1: the data that is to be signed is encoded using [DER]",
			Source:        lint.RFC5280,
			EffectiveDate: util.RFC2459Date,
		},
		Lint: NewBasicConstraintsInvalidDER,
	})
}

// Use an ad hoc structure so to be able to detect the undue
// presence of the IsCA field with its DEFAULT value (FALSE)
type BasicConstraints struct {
	IsCA    asn1.RawValue `asn1:"optional"`
	PathLen int           `asn1:"optional"`
}

type BasicConstraintsInvalidDER struct{}

func NewBasicConstraintsInvalidDER() lint.LintInterface {
	return &BasicConstraintsInvalidDER{}
}

func (l *BasicConstraintsInvalidDER) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.BasicConstOID)
}

func (l *BasicConstraintsInvalidDER) Execute(c *x509.Certificate) *lint.LintResult {
	ext := util.GetExtFromCert(c, util.BasicConstOID)

	basicConstr := BasicConstraints{}
	_, err := asn1.Unmarshal(ext.Value, &basicConstr)
	if err != nil {
		return &lint.LintResult{
			Status:  lint.Fatal,
			Details: "Could not parse the BasicConstraints extension",
		}
	}

	if basicConstr.IsCA.Tag == asn1.TagBoolean && // the cA field is present
		len(basicConstr.IsCA.Bytes) > 0 && // it has an explicit value
		basicConstr.IsCA.Bytes[0] == 0 { // the value is FALSE
		return &lint.LintResult{
			Status: lint.Error,
			Details: "The BasicConstraints extension has an invalid DER encoding; " +
				"fields with DEFAULT values must be omitted.",
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
