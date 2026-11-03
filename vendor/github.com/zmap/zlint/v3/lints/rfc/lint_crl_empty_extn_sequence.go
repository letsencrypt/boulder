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
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"encoding/asn1"
	"math/big"
	"time"

	"fmt"
)

// This lint checks that the crlEntryExtensions field of CRL entries, where present,
// is NOT an empty SEQUENCE, which is forbidden by RFC 5280 (see Appendix A.1).
// In fact, the crlEntryExtensions field is of type 'Extensions' which has the
// following ASN.1 syntax:
//    Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
// The SIZE constraint means that the SEQUENCE must contain at least 1 'Extension'
// (i.e. it cannot have a zero length). This lint returns an error upon encountering
// the first empty SEQUENCE (if any). It would be impractical to compile a list of
// all affected entries — which could be countless — and then list them all in the
// error message. On the other hand, if there is an entry with this problem in the
// CRL being examined, it is likely not the only one.

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_crl_empty_extn_sequence",
			Description:   "Checks that the crlEntryExtensions field of CRL entries is NOT an empty SEQUENCE",
			Citation:      "RFC 5280 (Appendix A.1)",
			Source:        lint.RFC5280,
			EffectiveDate: util.RFC5280Date,
		},
		Lint: NewCRLEmptyExtnSequence,
	})
}

type CRLEmptyExtnSequence struct{}

func NewCRLEmptyExtnSequence() lint.RevocationListLintInterface {
	return &CRLEmptyExtnSequence{}
}

func (l *CRLEmptyExtnSequence) CheckApplies(c *x509.RevocationList) bool {
	return true
}

type revokedCertificate struct {
	UserCertificate    *big.Int
	RevocationDate     time.Time
	CrlEntryExtensions asn1.RawValue `asn1:"optional"`
}

func (l *CRLEmptyExtnSequence) Execute(c *x509.RevocationList) *lint.LintResult {

	for _, rce := range c.RevokedCertificates {
		// Declared per entry: asn1.Unmarshal does not reset an absent optional
		// field, so a shared struct would carry over the previous entry's value.
		revCert := revokedCertificate{}
		_, err := asn1.Unmarshal(rce.Raw, &revCert)
		if err == nil {
			// Get the extensions of the current CRL entry
			ext := revCert.CrlEntryExtensions

			// crlEntryExtensions is OPTIONAL, so FullBytes is empty when absent.
			// Otherwise, 0x30 is the ASN.1 universal tag for SEQUENCE
			// and the byte at offset 1 is the length, which cannot be zero
			if len(ext.FullBytes) >= 2 && ext.FullBytes[0] == 0x30 && ext.FullBytes[1] == 0 {
				return &lint.LintResult{
					Status: lint.Error,
					Details: fmt.Sprintf(
						"The crlEntryExtensions field for CRL entry %x is an empty SEQUENCE (forbidden)",
						revCert.UserCertificate),
				}
			}
		} else {
			// This should never happen, but one never knows...
			return &lint.LintResult{
				Status:  lint.Fatal,
				Details: fmt.Sprintf("Cannot decode the CRL entry %x", rce.SerialNumber),
			}
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
