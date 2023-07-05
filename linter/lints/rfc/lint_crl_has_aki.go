package rfc

import (
	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/zmap/zlint/v3/lint"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// hasAKI checks RFC 5280, Section 5.2.1:
// Conforming CRL issuers MUST use the key identifier method, and MUST include
// this extension in all CRLs issued.
func hasAKI(crl *crl_x509.RevocationList) *lint.LintResult {
	if len(crl.AuthorityKeyId) == 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRLs MUST include the authority key identifier extension",
		}
	}
	aki := cryptobyte.String(crl.AuthorityKeyId)
	var akiBody cryptobyte.String
	if !aki.ReadASN1(&akiBody, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRL has a malformed authority key identifier extension",
		}
	}
	if !akiBody.PeekASN1Tag(cryptobyte_asn1.Tag(0).ContextSpecific()) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRLs MUST use the key identifier method in the authority key identifier extension",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
