package cabf_br

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

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type crlEcdsaSignatureAidEncoding struct{}

/*
*************************************************************************
BRs v2.3.1: 7.1.3.2 Signature AlgorithmIdentifier
All objects signed by a CA Private Key MUST conform to these requirements on the
use of the AlgorithmIdentifier or AlgorithmIdentifier-derived type in the
context of signatures.

In particular, it applies to all of the following objects and fields:
  - The signatureAlgorithm field of a CertificateList
  - The signature field of a TBSCertList
  - [...]

No other encodings are permitted for these fields.

BRs v2.3.1: 7.1.3.2.2 ECDSA
The CA SHALL use the appropriate signature algorithm and encoding based upon the
signing key used.

If the signing key is P-256, the signature MUST use ECDSA with SHA-256. When
encoded, the AlgorithmIdentifier MUST be byte-for-byte identical with the
following hex-encoded bytes: 300a06082a8648ce3d040302.

If the signing key is P-384, the signature MUST use ECDSA with SHA-384. When
encoded, the AlgorithmIdentifier MUST be byte-for-byte identical with the
following hex-encoded bytes: 300a06082a8648ce3d040303.

If the signing key is P-521, the signature MUST use ECDSA with SHA-512. When
encoded, the AlgorithmIdentifier MUST be byte-for-byte identical with the
following hex-encoded bytes: 300a06082a8648ce3d040304.

BRs v2.3.1: 7.2 (CRL Fields) requires CertificateList.signatureAlgorithm to be
byte-for-byte identical to tbsCertList.signature. zcrypto rejects a CRL where
they differ, so only tbsCertList.signature needs checking here.
**************************************************************************
*/
func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_crl_ecdsa_signature_encoding_correct",
			Description:   "For ECDSA, the signature algorithm must match the signing key (P-256/SHA-256, P-384/SHA-384, P-521/SHA-512) and the encoded AlgorithmIdentifier MUST be byte-for-byte identical with the specified encoding.",
			Citation:      "BRs v2.3.1: 7.1.3.2 and 7.1.3.2.2",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_1_7_4_Date,
		},
		Lint: NewCrlEcdsaSignatureAidEncoding,
	})
}

func NewCrlEcdsaSignatureAidEncoding() lint.RevocationListLintInterface {
	return &crlEcdsaSignatureAidEncoding{}
}

// A CRL carries no copy of the signing key, so the curve is inferred from the
// signature length. The limits are the maximum DER ECDSA-Sig-Value lengths:
// P-256: 2+2+2+33+33 = 72, P-384: 2+2+2+49+49 = 104, P-521: 2+2+2+67+67 = 140.
// A signature with unusually small r and s can be classified as a smaller
// curve than it was made with.
var ecdsaSignatureLimits = []struct {
	maxSignatureLen int
	curve           string
	algorithmID     []byte
}{
	{72, "P-256", []byte{0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}},
	{104, "P-384", []byte{0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03}},
	{140, "P-521", []byte{0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04}},
}

func (l *crlEcdsaSignatureAidEncoding) CheckApplies(r *x509.RevocationList) bool {
	return r.SignatureAlgorithm == x509.ECDSAWithSHA1 ||
		r.SignatureAlgorithm == x509.ECDSAWithSHA256 ||
		r.SignatureAlgorithm == x509.ECDSAWithSHA384 ||
		r.SignatureAlgorithm == x509.ECDSAWithSHA512 ||
		isSHA224WithECDSA(r)
}

// ecdsa-with-SHA224 has no x509.SignatureAlgorithm constant, so inspect the
// OID directly.
func isSHA224WithECDSA(r *x509.RevocationList) bool {
	encoded, err := util.GetSignatureAlgorithmInTBSCertListEncoded(r)
	if err != nil {
		return false
	}
	oid, err := util.GetAlgorithmIdentifierOID(encoded)
	return err == nil && oid.Equal(util.OidSignatureSHA224withECDSA)
}

func (l *crlEcdsaSignatureAidEncoding) Execute(r *x509.RevocationList) *lint.LintResult {
	encoded, err := util.GetSignatureAlgorithmInTBSCertListEncoded(r)
	if err != nil {
		return &lint.LintResult{Status: lint.Error, Details: err.Error()}
	}

	signatureSize := len(r.Signature)
	for _, limit := range ecdsaSignatureLimits {
		if signatureSize > limit.maxSignatureLen {
			continue
		}
		if !bytes.Equal(encoded, limit.algorithmID) {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: fmt.Sprintf("Encoding of signature algorithm does not match signing key on %s curve. Got the unsupported %s", limit.curve, hex.EncodeToString(encoded)),
			}
		}
		return &lint.LintResult{Status: lint.Pass}
	}
	return &lint.LintResult{
		Status:  lint.Error,
		Details: fmt.Sprintf("Encoding of signature algorithm does not match signing key. Got signature length %v", signatureSize),
	}
}
