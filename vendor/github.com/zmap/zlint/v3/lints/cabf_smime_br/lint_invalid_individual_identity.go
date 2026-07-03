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

package cabf_smime_br

import (
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_invalid_individual_identity",
			Description:   "Non-legacy IV and SV certificates... SHALL include either subject:givenName and/or subject:surname, or the subject:pseudonym.",
			Citation:      "CABF S/MIME BR 7.1.4.2.5 and 7.1.4.2.6",
			Source:        lint.CABFSMIMEBaselineRequirements,
			EffectiveDate: util.CABF_SMIME_BRs_1_0_0_Date,
		},
		Lint: NewInvalidPersonalSubject,
	})
}

type InvalidPersonalSubject struct{}

func NewInvalidPersonalSubject() lint.LintInterface {
	return &InvalidPersonalSubject{}
}

func (l *InvalidPersonalSubject) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && !util.IsLegacySMIMECertificate(c) &&
		(util.IsIndividualValidatedCertificate(c) || util.IsSponsorValidatedCertificate(c))
}

func (l *InvalidPersonalSubject) Execute(c *x509.Certificate) *lint.LintResult {

	if !isPseudonymPresent(c) && !isPersonalNamePresent(c) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Non-Legacy IV and SV S/MIME certificates MUST contain either a Personal Name or a Pseudonym",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

func isPersonalNamePresent(c *x509.Certificate) bool {
	return len(c.Subject.GivenName) > 0 || len(c.Subject.Surname) > 0
}

func isPseudonymPresent(c *x509.Certificate) bool {

	pseudonymOID := asn1.ObjectIdentifier{2, 5, 4, 65}

	for _, atv := range c.Subject.Names {
		if atv.Type.Equal(pseudonymOID) {
			return true
		}
	}
	return false
}
