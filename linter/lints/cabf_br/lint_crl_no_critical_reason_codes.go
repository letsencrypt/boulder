package cabfbr

import (
	"encoding/asn1"

	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/zmap/zlint/v3/lint"
)

// noCrticialReasons checks Baseline Requirements, Section 7.2.2.1:
// If present, [the reasonCode] extension MUST NOT be marked critical.
func noCriticalReasons(crl *crl_x509.RevocationList) *lint.LintResult {
	reasonCodeOID := asn1.ObjectIdentifier{2, 5, 29, 21} // id-ce-reasonCode
	for _, rc := range crl.RevokedCertificates {
		for _, ext := range rc.Extensions {
			if ext.Id.Equal(reasonCodeOID) && ext.Critical {
				return &lint.LintResult{
					Status:  lint.Error,
					Details: "CRL entry reasonCodes MUST NOT be critical",
				}
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
