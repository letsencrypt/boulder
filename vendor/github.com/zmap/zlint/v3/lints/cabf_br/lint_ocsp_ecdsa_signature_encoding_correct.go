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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
	"golang.org/x/crypto/ocsp"
)

type ocspEcdsaSignatureAidEncoding struct{}

/*
*************************************************************************
BRs v2.3.1: 7.1.3.2 Signature AlgorithmIdentifier
All objects signed by a CA Private Key MUST conform to these requirements on the
use of the AlgorithmIdentifier or AlgorithmIdentifier-derived type in the
context of signatures.

In particular, it applies to all of the following objects and fields:
  - [...]
  - The signatureAlgorithm field of a BasicOCSPResponse.

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
**************************************************************************
*/
func init() {
	lint.RegisterOcspResponseLint(&lint.OcspResponseLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_ocsp_ecdsa_signature_encoding_correct",
			Description:   "For ECDSA, the signature algorithm must match the signing key (P-256/SHA-256, P-384/SHA-384, P-521/SHA-512) and the encoded AlgorithmIdentifier MUST be byte-for-byte identical with the specified encoding.",
			Citation:      "BRs v2.3.1: 7.1.3.2 and 7.1.3.2.2",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_1_7_4_Date,
		},
		Lint: NewOcspEcdsaSignatureAidEncoding,
	})
}

func NewOcspEcdsaSignatureAidEncoding() lint.OcspResponseLintInterface {
	return &ocspEcdsaSignatureAidEncoding{}
}

func (l *ocspEcdsaSignatureAidEncoding) CheckApplies(o *ocsp.Response) bool {
	switch o.SignatureAlgorithm {
	case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return true
	}
	encoded, err := util.GetSignatureAlgorithmInBasicOCSPResponseEncoded(o)
	if err != nil {
		return false
	}
	oid, err := util.GetAlgorithmIdentifierOID(encoded)
	return err == nil && oid.Equal(util.OidSignatureSHA224withECDSA)
}

func (l *ocspEcdsaSignatureAidEncoding) Execute(o *ocsp.Response) *lint.LintResult {
	encoded, err := util.GetSignatureAlgorithmInBasicOCSPResponseEncoded(o)
	if err != nil {
		return &lint.LintResult{Status: lint.Error, Details: err.Error()}
	}

	// ocsp.ParseResponse verifies the signature against an embedded responder
	// certificate, so its key identifies the curve. Otherwise (CA-signed), fall
	// back to the signature-length heuristic used for CRLs.
	var curve string
	if o.Certificate != nil {
		if pub, ok := o.Certificate.PublicKey.(*ecdsa.PublicKey); ok {
			curve = pub.Curve.Params().Name
		}
	}

	for _, limit := range ecdsaSignatureLimits {
		if curve != "" && curve != limit.curve {
			continue
		}
		if curve == "" && len(o.Signature) > limit.maxSignatureLen {
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
	if curve != "" {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Signing key is on the unsupported curve " + curve,
		}
	}
	return &lint.LintResult{
		Status:  lint.Error,
		Details: fmt.Sprintf("Encoding of signature algorithm does not match signing key. Got signature length %v", len(o.Signature)),
	}
}
