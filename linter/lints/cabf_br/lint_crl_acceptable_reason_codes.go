package cabfbr

import (
	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/zmap/zlint/v3/lint"
)

// noZeroReasonCodes checks Baseline Requirements, Section 7.2.2.1:
// The CRLReason indicated MUST NOT be unspecified (0). If the reason for
// revocation is unspecified, CAs MUST omit reasonCode entry extension, if
// allowed by the previous requirements.
// By extension, it therefore also checks RFC 5280, Section 5.3.1:
// The reason code CRL entry extension SHOULD be absent instead of using the
// unspecified (0) reasonCode value.
func noZeroReasonCodes(crl *crl_x509.RevocationList) *lint.LintResult {
	for _, entry := range crl.RevokedCertificates {
		if entry.ReasonCode != nil && *entry.ReasonCode == 0 {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "CRL entries MUST NOT contain the unspecified (0) reason code",
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// noCertificateHolds checks Baseline Requirements, Section 7.2.2.1:
// The CRLReason MUST NOT be certificateHold (6).
func noCertificateHolds(crl *crl_x509.RevocationList) *lint.LintResult {
	for _, entry := range crl.RevokedCertificates {
		if entry.ReasonCode != nil && *entry.ReasonCode == 6 {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "CRL entries MUST NOT use the certificateHold (6) reason code",
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// hasMozReasonCodes checks MRSP v2.8 Section 6.1.1:
// When the CRLReason code is not one of the following, then the reasonCode extension MUST NOT be provided:
// - keyCompromise (RFC 5280 CRLReason #1);
// - privilegeWithdrawn (RFC 5280 CRLReason #9);
// - cessationOfOperation (RFC 5280 CRLReason #5);
// - affiliationChanged (RFC 5280 CRLReason #3); or
// - superseded (RFC 5280 CRLReason #4).
func hasMozReasonCodes(crl *crl_x509.RevocationList) *lint.LintResult {
	for _, rc := range crl.RevokedCertificates {
		if rc.ReasonCode == nil {
			continue
		}
		switch *rc.ReasonCode {
		case 1: // keyCompromise
		case 3: // affiliationChanged
		case 4: // superseded
		case 5: // cessationOfOperation
		case 9: // privilegeWithdrawn
			continue
		default:
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "CRLs MUST NOT include reasonCodes other than 1, 3, 4, 5, and 9",
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
