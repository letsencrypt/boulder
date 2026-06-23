package etsi

/*
 * ZLint Copyright 2025 Regents of the University of Michigan
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
	"fmt"
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type qcStatemPdsHttpsOnly struct{}

/************************************************************************

ETSI EN 319 412-5 V2.4.1 (2023-09)
https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.04.01_60/en_31941205v020401p.pdf#%5B%7B%22num%22%3A30%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C381%5D

4.3.4 QCStatement regarding location of PKI Disclosure Statements (PDS)
This QCStatement holds URLs to PKI Disclosure Statements (PDS) in accordance with Annex A of ETSI EN 319 411-1 [i.10].

Syntax:

esi4-qcStatement-5 QC-STATEMENT ::= { SYNTAX QcEuPDS IDENTIFIED
BY id-etsi-qcs-QcPDS }

QcEuPDS ::= PdsLocations //nolint:dupword

PdsLocations ::= SEQUENCE SIZE (1..MAX) OF PdsLocation //nolint:dupword // dup comes from the specification

PdsLocation::= SEQUENCE {
url IA5String,
language PrintableString (SIZE(2))} --ISO 639-1 language code

id-etsi-qcs-QcPDS OBJECT IDENTIFIER ::= { id-etsi-qcs 5 }

QCS-4.3.4-01: The language shall be as defined in ISO 639-1 [1].

QCS-4.3.4-02: Referenced PKI Disclosure Statements should be structured according to Annex A of ETSI
EN 319 411-1 [i.10].

The signature of the certificate does not cover the content of the PDS and hence does not protect the integrity of the
PDS which can change over time. End users trust in the accuracy of a PDS is therefore based on the mechanisms used
to protect the authenticity of the PDS.

QCS-4.3.4-03: As a minimum, a URL to a PDS provided in this statement shall use the "https" (https://) scheme, IETF
RFC 2818 [5] or later documents updating this specification

*************************************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_qcstatem_pds_must_have_https_only",
			Description:   "Checks that a QC Statement of the type id-etsi-qcs-QcPDS contains a URL that uses the https scheme.",
			Citation:      "ETSI EN 319 412 - 5 V2.4.1 (2023 - 09) / Section 4.3.4",
			Source:        lint.EtsiEsi,
			EffectiveDate: util.EtsiEn319_412_5_V2_4_1_Date,
		},
		Lint: NewQcStatemPdsHasHTTPSOnly,
	})
}

func NewQcStatemPdsHasHTTPSOnly() lint.LintInterface {
	return &qcStatemPdsHttpsOnly{}
}

func (l *qcStatemPdsHttpsOnly) CheckApplies(c *x509.Certificate) bool {
	qcEuPDS := &util.IdEtsiQcsQcEuPDS
	if !util.IsExtInCert(c, util.QcStateOid) {
		return false
	}
	if util.ParseQcStatem(util.GetExtFromCert(c, util.QcStateOid).Value, *qcEuPDS).IsPresent() {
		return true
	}
	return false
}

func (l *qcStatemPdsHttpsOnly) Execute(c *x509.Certificate) *lint.LintResult {

	ext := util.GetExtFromCert(c, util.QcStateOid)
	s := util.ParseQcStatem(ext.Value, util.IdEtsiQcsQcEuPDS)

	errString := s.GetErrorInfo()

	if len(errString) != 0 {
		return &lint.LintResult{Status: lint.Error, Details: "Could not parse qcStatement with PDS: " + errString}
	}

	pds := s.(util.EtsiQcPds)
	for _, loc := range pds.PdsLocations {
		if !strings.HasPrefix(loc.Url, "https://") {
			return &lint.LintResult{Status: lint.Error, Details: fmt.Sprintf("PDS URL %s does not use the https scheme", loc.Url)}
		}
	}

	return &lint.LintResult{Status: lint.Pass}

}
