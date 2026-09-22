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
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_crl_auth_key_id_only_contains_keyid",
			Description:   "The AuthKey extension must only contain the KeyIdentifier field.",
			Citation:      "BRs: 7.2.2",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_2_0_1_Date,
		},
		Lint: func() lint.RevocationListLintInterface { return &authKeyIDOnlyContainsKeyID{} },
	})
}

type authKeyIDOnlyContainsKeyID struct{}

func (l *authKeyIDOnlyContainsKeyID) CheckApplies(r *x509.RevocationList) bool {
	return true
}

func (l *authKeyIDOnlyContainsKeyID) Execute(r *x509.RevocationList) *lint.LintResult {
	for _, ext := range r.Extensions {
		if !ext.Id.Equal(util.AuthkeyOID) {
			continue
		}
		var authKey authKey
		rest, err := asn1.Unmarshal(ext.Value, &authKey)
		if err != nil {
			return &lint.LintResult{Status: lint.Error, Details: fmt.Sprintf("Failed to unmarshal authorityKeyIdentifier extension: %v", err)}
		}
		if len(rest) != 0 {
			return &lint.LintResult{Status: lint.Error, Details: "Unexpected trailing data after authorityKeyIdentifier extension"}
		}
		if authKey.KeyIdentifier == nil {
			return &lint.LintResult{Status: lint.Error, Details: "keyIdentifier field is missing in authorityKeyIdentifier extension"}
		}
		if authKey.AuthorityCertIssuer != nil || authKey.AuthorityCertSerialNumber != nil {
			return &lint.LintResult{Status: lint.Error, Details: "Forbidden authorityCertIssuer or authorityCertSerialNumber in authorityKeyIdentifier extension"}
		}
	}
	return &lint.LintResult{Status: lint.Pass}

}

type authKey struct {
	KeyIdentifier             []byte   `asn1:"optional,tag:0"`
	AuthorityCertIssuer       []byte   `asn1:"optional,tag:1"`
	AuthorityCertSerialNumber *big.Int `asn1:"optional,tag:2"`
}
