/*
 * ZLint Copyright 2018 Regents of the University of Michigan
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

package lints

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type evLocalityMissing struct{}

func (l *evLocalityMissing) Initialize() error {
	return nil
}

func (l *evLocalityMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsEV(c.PolicyIdentifiers)
}

func (l *evLocalityMissing) Execute(c *x509.Certificate) *LintResult {
	if util.TypeInName(&c.Subject, util.LocalityNameOID) {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Error}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ev_locality_name_missing",
		Description:   "EV certificates must include localityName in subject",
		Citation:      "BRs: 7.1.6.1",
		Source:        CABFBaselineRequirements,
		EffectiveDate: util.ZeroDate,
		Lint:          &evLocalityMissing{},
	})
}
