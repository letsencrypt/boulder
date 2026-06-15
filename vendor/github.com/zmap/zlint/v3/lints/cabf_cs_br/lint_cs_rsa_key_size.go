package cabf_cs_br

import (
	"crypto/rsa"

	"github.com/zmap/zcrypto/x509"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/*6.1.5.2 Code signing Certificate and Timestamp Authority key sizes
For Keys corresponding to Subscriber code signing and Timestamp Authority Certificates:
• If the Key is RSA, then the modulus MUST be at least 3072 bits in length.
• If the Key is ECDSA, then the curve MUST be one of NIST P‐256, P‐384, or P‐521.
• If the Key is DSA, then one of the following key parameter options MUST be used:
• Key length (L) of 2048 bits and modulus length (N) of 224 bits
• Key length (L) of 2048 bits and modulus length (N) of 256 bits*/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cs_rsa_key_size",
			Description:   "If the Key is RSA, then the modulus MUST be at least 3072 bits in length",
			Citation:      "CABF CS BRs 6.1.5.2",
			Source:        lint.CABFCSBaselineRequirements,
			EffectiveDate: util.CABF_CS_BRs_1_2_Date,
		},
		Lint: NewCsRsaKeySize,
	})
}

type csRsaKeySize struct{}

func NewCsRsaKeySize() lint.CertificateLintInterface {
	return &csRsaKeySize{}
}

func (l *csRsaKeySize) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *csRsaKeySize) Execute(c *x509.Certificate) *lint.LintResult {
	rsaKey, ok := c.PublicKey.(*rsa.PublicKey)
	if !ok {
		return &lint.LintResult{Status: lint.NA}
	}

	// If the Key is RSA, then the modulus MUST be at least 3072 bits in length.
	if rsaKey.N.BitLen() < 3072 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Code Signing RSA key modulus MUST be at least 3072 bits in length.",
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
