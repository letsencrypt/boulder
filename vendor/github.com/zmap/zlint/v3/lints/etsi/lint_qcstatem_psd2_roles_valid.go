/*
 * ZLint Copyright 2026 Regents of the University of Michigan
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

package etsi

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

// psd2KnownRoles is the full set of role OIDs ETSI TS 119 495 Annex A
// currently defines, verified byte-for-byte against the current edition
// (V1.8.1), keyed by the OID's dotted string form. Roles whose OID isn't
// in this table are intentionally not validated — see GEN-5.2.2-4 in the
// block comment below.
var psd2KnownRoles = map[string]string{
	"0.4.0.19495.1.0":  "Unspecified",
	"0.4.0.19495.1.1":  "PSP_AS",
	"0.4.0.19495.1.2":  "PSP_PI",
	"0.4.0.19495.1.3":  "PSP_AI",
	"0.4.0.19495.1.4":  "PSP_IC",
	"0.4.0.19495.1.5":  "PSP_CB",
	"0.4.0.19495.1.6":  "PSP_PA",
	"0.4.0.19495.1.51": "VOP_RS",
	"0.4.0.19495.1.52": "VOP_VS",
}

type qcStatemPsd2RolesValid struct{}

// ETSI TS 119 495 V1.1.2 (2018-07), Section 5.2.2:
//
//	REG-5.2.2-5: The TSP shall ensure that the name in roleOfPspName is
//	the one associated with the role object identifier held in
//	roleOfPspOid.
//
//	GEN-5.2.2-4: For any other role the role object identifier and role
//	name should be defined and registered by an organization recognized
//	at the European or national level.
func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_qcstatem_psd2_roles_valid",
			Description:   "Checks that, for each role in a PSD2 QcStatement's RolesOfPSP whose OID is one of ETSI's registered role OIDs, the role name exactly matches that OID; roles with an unrecognized OID are not checked",
			Citation:      "ETSI TS 119 495 V1.1.2 (2018-07), Section 5.2.2, REG-5.2.2-5",
			Source:        lint.EtsiEsi,
			EffectiveDate: util.EtsiTs119495_V1_1_2_Date,
		},
		Lint: NewQcStatemPsd2RolesValid,
	})
}

func NewQcStatemPsd2RolesValid() lint.LintInterface {
	return &qcStatemPsd2RolesValid{}
}

func (l *qcStatemPsd2RolesValid) CheckApplies(c *x509.Certificate) bool {
	if !util.IsExtInCert(c, util.QcStateOid) {
		return false
	}
	return util.ParseQcStatem(util.GetExtFromCert(c, util.QcStateOid).Value, util.IdEtsiPsd2Statem).IsPresent()
}

func (l *qcStatemPsd2RolesValid) Execute(c *x509.Certificate) *lint.LintResult {
	ext := util.GetExtFromCert(c, util.QcStateOid)
	s := util.ParseQcStatem(ext.Value, util.IdEtsiPsd2Statem)
	if s.GetErrorInfo() != "" {
		return &lint.LintResult{Status: lint.Error, Details: s.GetErrorInfo()}
	}
	psd2, ok := s.(util.EtsiPsd2)
	if !ok {
		return &lint.LintResult{Status: lint.Fatal, Details: "parsed QC statement is not of type EtsiPsd2"}
	}

	for _, role := range psd2.Decoded.RolesOfPSP {
		oid := role.RoleOfPspOid.String()
		name, ok := psd2KnownRoles[oid]
		if !ok {
			continue
		}
		if role.RoleOfPspName != name {
			return &lint.LintResult{Status: lint.Error, Details: fmt.Sprintf(
				"role name %q does not match the expected name %q for role OID %s",
				role.RoleOfPspName, name, oid)}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
