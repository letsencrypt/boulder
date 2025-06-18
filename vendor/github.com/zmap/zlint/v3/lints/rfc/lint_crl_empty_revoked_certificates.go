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
 * Contributed by Adriano Santoni <adriano.santoni@staff.aruba.it>
 * of ACTALIS S.p.A. (www.actalis.com).
 */

package rfc

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_crl_empty_revoked_certificates",
			Description:   "When there are no revoked certificates, the revoked certificates list MUST be absent",
			Citation:      "RFC5280 §5.1.2.6",
			Source:        lint.RFC5280,
			EffectiveDate: util.RFC5280Date,
		},
		Lint: NewEmptyRevokedCertificates,
	})
}

type emptyRevokedCertificates struct{}

type RevokedCertificate struct {
	UserCertificate    *big.Int
	RevocationDate     time.Time
	CrlEntryExtensions asn1.RawValue `asn1:"optional"`
}

type TBSCertList struct {
	Version             int `asn1:"optional"`
	Signature           pkix.AlgorithmIdentifier
	Issuer              asn1.RawValue
	ThisUpdate          time.Time
	NextUpdate          time.Time            `asn1:"optional"`
	RevokedCertificates []RevokedCertificate `asn1:"optional"`
	CrlExtensions       asn1.RawValue        `asn1:"tag:0,optional"`
}

type CertificateList struct {
	TbsCertList        TBSCertList
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

func NewEmptyRevokedCertificates() lint.RevocationListLintInterface {
	return &emptyRevokedCertificates{}
}

func (l *emptyRevokedCertificates) CheckApplies(c *x509.RevocationList) bool {
	return true
}

func (l *emptyRevokedCertificates) Execute(c *x509.RevocationList) *lint.LintResult {

	// We have to re-unmarshal the CRL in our own way, as x.509 RevocationList
	// does not allow the verification we want to do here
	var certList CertificateList
	_, err := asn1.Unmarshal(c.Raw, &certList)
	if err != nil {
		return &lint.LintResult{
			Status:  lint.Fatal,
			Details: "Failed to decode CRL",
		}
	}

	if certList.TbsCertList.RevokedCertificates != nil {
		if len(certList.TbsCertList.RevokedCertificates) == 0 {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "CRL contains an empty revokedCertificates element",
			}
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
