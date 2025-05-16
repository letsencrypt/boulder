package rfc

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

import (
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
	"golang.org/x/crypto/ocsp"
)

type OCSPThisUpdateNotAfterProducedAt struct{}

/*
RFC 6960: 2.4
thisUpdate      The most recent time at which the status being
                indicated is known by the responder to have been
                correct.
producedAt      The time at which the OCSP responder signed this
                response.
*/

func init() {
	lint.RegisterOcspResponseLint(&lint.OcspResponseLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_this_update_not_after_produced_at",
			Description:   "The value of thisUpdate MUST be prior to the time at which the response is produced, i.e., the value of producedAt",
			Source:        lint.RFC6960,
			Citation:      "RFC 6960: 2.4",
			EffectiveDate: util.RFC6960Date,
		},
		Lint: NewOCSPThisUpdateNotAfterProducedAt,
	})
}

func NewOCSPThisUpdateNotAfterProducedAt() lint.OcspResponseLintInterface {
	return OCSPThisUpdateNotAfterProducedAt{}
}

func (l OCSPThisUpdateNotAfterProducedAt) CheckApplies(c *ocsp.Response) bool {
	return true
}

func (l OCSPThisUpdateNotAfterProducedAt) Execute(c *ocsp.Response) *lint.LintResult {
	if c.ThisUpdate.After(c.ProducedAt) {
		return &lint.LintResult{Status: lint.Error}
	}
	return &lint.LintResult{Status: lint.Pass}
}
