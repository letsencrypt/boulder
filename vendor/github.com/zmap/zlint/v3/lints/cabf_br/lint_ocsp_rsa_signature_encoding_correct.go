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
	"encoding/hex"
	"time"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
	"golang.org/x/crypto/ocsp"
)

type ocspRsaSignatureAidEncoding struct{}

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

BRs v2.3.1: 7.1.3.2.1 RSA
The CA SHALL use one of the following signature algorithms and encodings.
When encoded, the AlgorithmIdentifier MUST be byte-for-byte identical with
the specified hex-encoded bytes.

  - RSASSA-PKCS1-v1_5 with SHA-256: 300d06092a864886f70d01010b0500
  - RSASSA-PKCS1-v1_5 with SHA-384: 300d06092a864886f70d01010c0500
  - RSASSA-PKCS1-v1_5 with SHA-512: 300d06092a864886f70d01010d0500
  - RSASSA-PSS with SHA-256, MGF-1 with SHA-256, and a salt length of 32 bytes
  - RSASSA-PSS with SHA-384, MGF-1 with SHA-384, and a salt length of 48 bytes
  - RSASSA-PSS with SHA-512, MGF-1 with SHA-512, and a salt length of 64 bytes

Until 2026-09-15, the CA MAY use RSASSA-PKCS1-v1_5 with SHA-1
(300d06092a864886f70d0101050500) if, among other conditions, when used within
an OCSP response "The producedAt field value of the ResponseData MUST be
earlier than 2022-06-01 00:00:00 UTC".
**************************************************************************
*/
func init() {
	lint.RegisterOcspResponseLint(&lint.OcspResponseLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_ocsp_rsa_signature_encoding_correct",
			Description:   "For RSA, the encoded signatureAlgorithm of a BasicOCSPResponse MUST be byte-for-byte identical with one of the permitted encodings.",
			Citation:      "BRs v2.3.1: 7.1.3.2 and 7.1.3.2.1",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_1_7_4_Date,
		},
		Lint: NewOcspRsaSignatureAidEncoding,
	})
}

func NewOcspRsaSignatureAidEncoding() lint.OcspResponseLintInterface {
	return &ocspRsaSignatureAidEncoding{}
}

var (
	oidPKCS1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1}

	permittedRsaSignatureAids = map[string]string{
		"300d06092a864886f70d01010b0500": "RSASSA-PKCS1-v1_5 with SHA-256",
		"300d06092a864886f70d01010c0500": "RSASSA-PKCS1-v1_5 with SHA-384",
		"300d06092a864886f70d01010d0500": "RSASSA-PKCS1-v1_5 with SHA-512",
		"304106092a864886f70d01010a3034a00f300d0609608648016503040201" +
			"0500a11c301a06092a864886f70d010108300d0609608648016503040201" +
			"0500a203020120": "RSASSA-PSS with SHA-256",
		"304106092a864886f70d01010a3034a00f300d0609608648016503040202" +
			"0500a11c301a06092a864886f70d010108300d0609608648016503040202" +
			"0500a203020130": "RSASSA-PSS with SHA-384",
		"304106092a864886f70d01010a3034a00f300d0609608648016503040203" +
			"0500a11c301a06092a864886f70d010108300d0609608648016503040203" +
			"0500a203020140": "RSASSA-PSS with SHA-512",
	}

	sha1WithRSAEncryptionAid = "300d06092a864886f70d0101050500"
	sha1OcspSunset           = time.Date(2022, time.June, 1, 0, 0, 0, 0, time.UTC)
)

func (l *ocspRsaSignatureAidEncoding) CheckApplies(o *ocsp.Response) bool {
	encoded, err := util.GetSignatureAlgorithmInBasicOCSPResponseEncoded(o)
	if err != nil {
		return false
	}
	oid, err := util.GetAlgorithmIdentifierOID(encoded)
	if err != nil {
		return false
	}
	return len(oid) == len(oidPKCS1)+1 && oid[:len(oidPKCS1)].Equal(oidPKCS1)
}

func (l *ocspRsaSignatureAidEncoding) Execute(o *ocsp.Response) *lint.LintResult {
	encoded, err := util.GetSignatureAlgorithmInBasicOCSPResponseEncoded(o)
	if err != nil {
		return &lint.LintResult{Status: lint.Error, Details: err.Error()}
	}
	encodedHex := hex.EncodeToString(encoded)
	if _, ok := permittedRsaSignatureAids[encodedHex]; ok {
		return &lint.LintResult{Status: lint.Pass}
	}
	if encodedHex == sha1WithRSAEncryptionAid && o.ProducedAt.Before(sha1OcspSunset) {
		return &lint.LintResult{Status: lint.Pass}
	}
	return &lint.LintResult{
		Status:  lint.Error,
		Details: "Encoding of RSA signature algorithm is not permitted. Got " + encodedHex,
	}
}
