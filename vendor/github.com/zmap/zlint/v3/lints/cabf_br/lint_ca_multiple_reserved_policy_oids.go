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
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_ca_multiple_reserved_policy_oids",
			Description:   "The CA MUST include exactly one Reserved Certificate Policy Identifier",
			Citation:      "CABF BRs §7.1.2.10.5, Table 73 (Policy Restricted)",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_2_0_0_Date,
		},
		Lint: NewCAMultipleReservedPolicyOIDs,
	})
}

type CAMultipleReservedPolicyOIDs struct {
	CrossCert bool `comment:"Set this to true if the certificate to be linted is a cross-certificate"`
}

func NewCAMultipleReservedPolicyOIDs() lint.LintInterface {
	return &CAMultipleReservedPolicyOIDs{
		CrossCert: false,
	}
}

func (l *CAMultipleReservedPolicyOIDs) Configure() interface{} {
	return l
}

func (l *CAMultipleReservedPolicyOIDs) CheckApplies(c *x509.Certificate) bool {
	// Exclude non-policy-restricted SubCAs and cross-certificates
	return util.IsSubCA(c) && isPolicyRestricted(c) && !l.CrossCert
}

func (l *CAMultipleReservedPolicyOIDs) Execute(c *x509.Certificate) *lint.LintResult {
	if hasMultipleReservedPolicyOIDs(c) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "A Subordinate CA certificate MUST include exactly one Reserved Certificate Policy Identifier",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// By definition, a Policy Restricted CA is one that does NOT
// contain the anyPolicy OID in its CertificatePolicies extension
func isPolicyRestricted(c *x509.Certificate) bool {
	return !util.SliceContainsOID(c.PolicyIdentifiers, util.AnyPolicyOID)
}

func hasMultipleReservedPolicyOIDs(c *x509.Certificate) bool {
	cabfReservedPolicyOIDs := []asn1.ObjectIdentifier{
		util.BRDomainValidatedOID,
		util.BROrganizationValidatedOID,
		util.BRIndividualValidatedOID,
		util.BRExtendedValidatedOID,
	}

	// This way we also detect the weird case of multiple instances of
	// the same reserved policy OID, but this would still be an error...
	alreadyFoundOne := false
	for _, oid := range c.PolicyIdentifiers {
		if util.SliceContainsOID(cabfReservedPolicyOIDs, oid) {
			if alreadyFoundOne {
				return true
			} else {
				alreadyFoundOne = true
			}
		}
	}
	return false
}
