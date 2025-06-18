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
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_precert_with_sct_list",
			Description:   "SCTs must be embedded in the final certificate, not in a precertificate",
			Citation:      "RFC 6962 §3.3",
			Source:        lint.RFC6962,
			EffectiveDate: util.RFC6962Date,
		},
		Lint: NewPreCertWithSCTList,
	})
}

type preCertWithSCTList struct{}

func NewPreCertWithSCTList() lint.LintInterface {
	return &preCertWithSCTList{}
}

func (l *preCertWithSCTList) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.CtPoisonOID)
}

func (l *preCertWithSCTList) Execute(c *x509.Certificate) *lint.LintResult {
	if util.IsExtInCert(c, util.TimestampOID) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Precertificates must not contain the SignedCertificateTimestampList extension",
		}
	} else {
		return &lint.LintResult{Status: lint.Pass}
	}
}
