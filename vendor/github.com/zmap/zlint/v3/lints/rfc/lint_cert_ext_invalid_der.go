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

	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cert_ext_invalid_der",
			Description:   "Checks that the 'critical' flag of extensions is not FALSE when present (as per DER encoding)",
			Citation:      "RFC 5280 $4.2",
			Source:        lint.RFC5280,
			EffectiveDate: util.RFC5280Date,
		},
		Lint: NewCertExtensionInvalidDER,
	})
}

type certExtensionInvalidDER struct{}

/*
 * Modified syntax w/respect to RFC 5280, so we can detect whether
 * the critical field is actually present in the DER encoding
 */
type Extension struct {
	Id asn1.ObjectIdentifier
	// This is either the 'critical' or the 'extnValue' field (see RFC 5280 section 4.1)
	// We can discriminate based on tag, since the two fields are of different ASN.1 types
	Field2 asn1.RawValue
	// If this is present, it can only be the 'extnValue' field
	// We need to be able to capture it, but we do not deal with it
	Field3 asn1.RawValue `asn1:"optional"`
}

// This is just plain RFC 5280
type Certificate struct {
	TbsCertificate     TBSCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// Simplified with respect to RFC 5280, as we are not interested in most fields here
type TBSCertificate struct {
	Version         int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber    *big.Int
	SignatureAlgo   pkix.AlgorithmIdentifier
	Issuer          asn1.RawValue
	Validity        asn1.RawValue
	Subject         asn1.RawValue
	PublicKey       asn1.RawValue
	IssuerUniqueId  asn1.BitString `asn1:"optional,tag:1"`
	SubjectUniqueId asn1.BitString `asn1:"optional,tag:2"`
	Extensions      []Extension    `asn1:"omitempty,optional,explicit,tag:3"`
}

func NewCertExtensionInvalidDER() lint.LintInterface {
	return &certExtensionInvalidDER{}
}

func (l *certExtensionInvalidDER) CheckApplies(c *x509.Certificate) bool {
	// This lint applies to any kind of certificate
	return true
}

func (l *certExtensionInvalidDER) Execute(c *x509.Certificate) *lint.LintResult {

	// Re-decode certificate based on an ad-hoc target struct
	var cert Certificate
	_, err := asn1.Unmarshal(c.Raw, &cert)

	// This should never happen
	if err != nil {
		return &lint.LintResult{
			Status:  lint.Fatal,
			Details: "Failed to decode certificate",
		}
	}

	for _, ext := range cert.TbsCertificate.Extensions {
		if ext.Field2.Tag == asn1.TagBoolean {
			// This is the 'critical' flag
			if ext.Field2.Bytes[0] == 0 {
				// This a BOOLEAN FALSE
				return &lint.LintResult{
					Status:  lint.Error,
					Details: fmt.Sprintf("The %v extension is not properly DER-encoded ('critical' must be absent when FALSE)", ext.Id),
				}
			}
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
