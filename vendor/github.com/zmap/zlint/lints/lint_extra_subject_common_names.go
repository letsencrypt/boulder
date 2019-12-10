/*
 * ZLint Copyright 2019 Regents of the University of Michigan
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

type extraSubjectCommonNames struct{}

func (l *extraSubjectCommonNames) Initialize() error {
	return nil
}

func (l *extraSubjectCommonNames) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *extraSubjectCommonNames) Execute(c *x509.Certificate) *LintResult {
	// Multiple subject commonName fields are not expressly prohibited by section
	// 7.1.4.2.2 but do seem to run afoul of the intent. For that reason we return
	// only a Warn level finding here.
	if len(c.Subject.CommonNames) > 1 {
		return &LintResult{Status: Warn}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "w_extra_subject_common_names",
		Description:   "if present the subject commonName field MUST contain a single IP address or Fully-Qualified Domain Name",
		Citation:      "BRs: 7.1.4.2.2",
		Source:        CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          &extraSubjectCommonNames{},
	})
}
