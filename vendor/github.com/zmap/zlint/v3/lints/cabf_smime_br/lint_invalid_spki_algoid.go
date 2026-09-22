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

// This lint checks that the AlgorithmIdentifier, within the SubjectKeyInfo field,
// is valid according to the CABF S/MIME BR section xxx. It does so by comparing
// the entire DER encoding of the AlgorithmIdentifier with a list of allowed
// encodings, as set out in the BR. Since a few PQC algorithms have been added
// by SCMxx to the initial list of allowed algorithms in BR 1.0.0, we perform
// this check taking into account the issuance date (notBefore) of the certificate.

package cabf_smime_br

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"bytes"
	"encoding/asn1"
	"fmt"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_invalid_spki_algoid",
			Description:   "Checks that SubjectPublicKeyInfo.AlgorithmIdentifier is allowed, including PQC algorithms.",
			Citation:      "CABF S/MIME BR 7.1.3.1",
			Source:        lint.CABFSMIMEBaselineRequirements,
			EffectiveDate: util.CABF_SMIME_BRs_1_0_11_Date,
		},
		Lint: NewInvalidSPKIAlgoId,
	})
}

type InvalidSPKIAlgoId struct{}

func NewInvalidSPKIAlgoId() lint.LintInterface {
	return &InvalidSPKIAlgoId{}
}

func (l *InvalidSPKIAlgoId) CheckApplies(c *x509.Certificate) bool {
	return true
}

func (l *InvalidSPKIAlgoId) Execute(c *x509.Certificate) *lint.LintResult {
	var allowedAlgoIds = [12][]byte{
		// RSA
		{0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00},
		// P-256
		{0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
		// P-384
		{0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22},
		// P-521
		{0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23},
		// EdDSA Curve25519
		{0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70},
		// EdDSA Curve448
		{0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71},
		// ML-DSA-44
		{0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11},
		// ML-DSA-65
		{0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12},
		// ML-DSA-87
		{0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13},
		// ML-KEM-512
		{0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01},
		// ML-KEM-768
		{0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02},
		// ML-KEM-1024
		{0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03},
	}
	type SubjectPublicKeyInfo struct {
		Algorithm        asn1.RawValue
		SubjectPublicKey asn1.BitString
	}
	spki := SubjectPublicKeyInfo{}
	_, err := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &spki)
	if err != nil {
		return &lint.LintResult{
			Status:  lint.Fatal,
			Details: fmt.Sprintf("Cannot decode SubjectPublicKeyInfo: %v", err),
		}
	}
	for _, algoId := range allowedAlgoIds {
		if bytes.Equal(spki.Algorithm.FullBytes, algoId) {
			return &lint.LintResult{Status: lint.Pass}
		}
	}
	return &lint.LintResult{
		Status:  lint.Error,
		Details: fmt.Sprintf("Invalid Subject Public Key Algorithm Identifier: %X", spki.Algorithm.FullBytes),
	}
}
