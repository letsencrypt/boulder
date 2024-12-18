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
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type revokedCertificates struct{}

/*
RFC 5280: 5.1.2.6

	When there are no revoked certificates, the revoked certificates list
	MUST be absent.
*/
func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_crl_revoked_certificates_field_must_be_empty",
			Description:   "When the revokedCertificates field is empty, it MUST be absent from the DER-encoded ASN.1 data structure.",
			Citation:      "RFC 5280: 5.1.2.6",
			Source:        lint.RFC5280,
			EffectiveDate: util.RFC5280Date,
		},
		Lint: NewEmptyRevokedCerts,
	})
}

func NewEmptyRevokedCerts() lint.RevocationListLintInterface {
	return &revokedCertificates{}
}

func (l *revokedCertificates) CheckApplies(c *x509.RevocationList) bool {
	// This lint is to verify that the TBSCertList.revokedCertificates field,
	// when empty, is indeed missing from the DER-encoded ASN.1 bytes.
	if c != nil && len(c.RevokedCertificates) == 0 {
		return true
	}

	return false
}

func (l *revokedCertificates) Execute(c *x509.RevocationList) *lint.LintResult {
	// This is a modified version of x509.ParseRevocationList that extracts the
	// raw DER-encoded bytes that comprise a CRL and parses away layers until
	// the optional `revokedCertificates` field of a TBSCertList is either found
	// or confirmed to be missing from the ASN.1 data structure.
	input := cryptobyte.String(c.Raw)

	// Extract the CertificateList
	if !input.ReadASN1(&input, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Fatal, Details: "malformed CRL"}
	}

	var tbs cryptobyte.String
	// Extract the TBSCertList from the CertificateList
	if !input.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Fatal, Details: "malformed TBS CRL"}
	}

	// Skip optional version
	tbs.SkipOptionalASN1(cryptobyte_asn1.INTEGER)

	// Skip the signature
	tbs.SkipASN1(cryptobyte_asn1.SEQUENCE)

	// Skip the issuer
	tbs.SkipASN1(cryptobyte_asn1.SEQUENCE)

	// SkipOptionalASN1 is identical to SkipASN1 except that it also does a
	// peek. We'll handle the non-optional thisUpdate with these double peeks
	// because there's no harm doing so.
	skipTime := func(s *cryptobyte.String) {
		switch {
		case s.PeekASN1Tag(cryptobyte_asn1.UTCTime):
			s.SkipOptionalASN1(cryptobyte_asn1.UTCTime)
		case s.PeekASN1Tag(cryptobyte_asn1.GeneralizedTime):
			s.SkipOptionalASN1(cryptobyte_asn1.GeneralizedTime)
		}
	}

	// Skip thisUpdate
	skipTime(&tbs)

	// Skip optional nextUpdate
	skipTime(&tbs)

	// Finally, the field which we care about: revokedCertificates. This will
	// not trigger on the next field `crlExtensions` because that has
	// context-specific tag [0] and EXPLICIT encoding, not `SEQUENCE` and is
	// therefore a safe place to end this venture.
	if tbs.PeekASN1Tag(cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Error, Details: "When there are no revoked certificates, the revoked certificates list	MUST be absent."}
	}

	return &lint.LintResult{Status: lint.Pass}
}
