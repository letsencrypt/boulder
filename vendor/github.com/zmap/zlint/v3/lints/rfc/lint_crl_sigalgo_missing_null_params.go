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

package rfc

import (
	"bytes"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

/*
	From RFC 4055 section-6:

	-- When the following OIDs are used in an AlgorithmIdentifier, the
	-- parameters MUST be present and MUST be NULL.

	sha224WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 14 }

	sha256WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 11 }

	sha384WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 12 }

	sha512WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 13 }
*/

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_crl_sigalgo_missing_null_params",
			Description:   "Checks for mandatory NULL parameters in the SignatureAlgorithm",
			Citation:      "RFC 4055 Section 6",
			Source:        lint.RFC5280, // RFC4055 is referenced in RFC 5280, Section 1
			EffectiveDate: util.RFC5280Date,
		},
		Lint: NewCRLSigAlgoMissingNullParams,
	})
}

type CRLSigAlgoMissingNullParams struct{}

func NewCRLSigAlgoMissingNullParams() lint.RevocationListLintInterface {
	return &CRLSigAlgoMissingNullParams{}
}

func (l *CRLSigAlgoMissingNullParams) CheckApplies(c *x509.RevocationList) bool {
	return true
}

var (
	sha224WithRSAEncryption = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0xe}
	sha256WithRSAEncryption = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0xb}
	sha384WithRSAEncryption = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0xc}
	sha512WithRSAEncryption = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0xd}
)

func (l *CRLSigAlgoMissingNullParams) Execute(c *x509.RevocationList) *lint.LintResult {
	input := cryptobyte.String(c.Raw)

	// Read the outer CRL sequence (CertificateList)
	var crlBytes cryptobyte.String
	if !input.ReadASN1(&crlBytes, asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Fatal, Details: "Could not parse CRL"}
	}

	// Skip the tbsCertList element
	if !crlBytes.SkipASN1(asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Fatal, Details: "Could not parse CRL"}
	}

	// Read the signatureAlgorithm element
	var signatureAlgorithmBytes cryptobyte.String
	if !crlBytes.ReadASN1(&signatureAlgorithmBytes, asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Fatal, Details: "Could not parse CRL"}
	}

	// Read the algorithm element
	var algoBytes cryptobyte.String
	if !signatureAlgorithmBytes.ReadASN1(&algoBytes, asn1.OBJECT_IDENTIFIER) {
		return &lint.LintResult{Status: lint.Fatal, Details: "Could not parse CRL"}
	}

	if bytes.Equal(algoBytes, sha224WithRSAEncryption) ||
		bytes.Equal(algoBytes, sha256WithRSAEncryption) ||
		bytes.Equal(algoBytes, sha384WithRSAEncryption) ||
		bytes.Equal(algoBytes, sha512WithRSAEncryption) {

		// Attempt to read the parameters element
		var nullBytes cryptobyte.String
		var nullFound bool
		if !signatureAlgorithmBytes.ReadOptionalASN1(&nullBytes, &nullFound, asn1.NULL) {
			return &lint.LintResult{Status: lint.Fatal, Details: "Could not parse CRL"}
		}

		if !nullFound {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "Missing required NULL parameter in the SignatureAlgorithm element",
			}
		}

		// This should never happen, as invalid DER is caught upstream,
		// but let's check it for good measure
		if len(nullBytes) != 0 {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "Invalid DER encoding of NULL in the SignatureAlgorithm element",
			}
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
