package rfc

import (
	"encoding/asn1"

	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/zmap/zlint/v3/lint"
)

// hasNumber checks RFC 5280, Section 5.2.3:
// CRL issuers conforming to this profile MUST include this extension in all
// CRLs and MUST mark this extension as non-critical. Conforming CRL issuers
// MUST NOT use CRLNumber values longer than 20 octets.
func hasNumber(crl *crl_x509.RevocationList) *lint.LintResult {
	if crl.Number == nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRLs MUST include the CRL number extension",
		}
	}

	crlNumberOID := asn1.ObjectIdentifier{2, 5, 29, 20} // id-ce-cRLNumber
	ext := getExtWithOID(crl.Extensions, crlNumberOID)
	if ext != nil && ext.Critical {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRL Number MUST NOT be marked critical",
		}
	}

	numBytes := crl.Number.Bytes()
	if len(numBytes) > 20 || (len(numBytes) == 20 && numBytes[0]&0x80 != 0) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRL Number MUST NOT be longer than 20 octets",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
