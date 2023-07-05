package cpcps

import (
	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zlint/v3/lint"
)

// hasNoCertIssuers checks that the CRL does not have any entries with the
// Certificate Issuer extension (RFC 5280, Section 5.3.3). There is no
// requirement against this, but the presence of this extension would mean that
// the CRL includes certificates issued by an issuer other than the one signing
// the CRL itself, which we don't want to do.
func hasNoCertIssuers(crl *crl_x509.RevocationList) *lint.LintResult {
	certIssuerOID := asn1.ObjectIdentifier{2, 5, 29, 29} // id-ce-certificateIssuer
	for _, entry := range crl.RevokedCertificates {
		if getExtWithOID(entry.Extensions, certIssuerOID) != nil {
			return &lint.LintResult{
				Status:  lint.Notice,
				Details: "CRL has an entry with a Certificate Issuer extension",
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
