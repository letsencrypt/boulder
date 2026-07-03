package cabf_cs_br

import (
	"crypto/ecdsa"

	"github.com/zmap/zcrypto/x509"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/*6.1.5.2 Code signing Certificate and Timestamp Authority key sizes
If the Key is ECDSA, then the curve MUST be one of NIST P-256, P-384, or P-521.

6.1.6 Public key parameters generation and quality checking
ECDSA: The CA SHOULD confirm the validity of all keys using either the ECC Full
Public Key Validation Routine or the ECC Partial Public Key Validation Routine.
[Source: Sections 5.6.2.3.2 and 5.6.2.3.3, respectively, of NIST SP 800-56A: Revision 2]
*/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cs_ecdsa_prohibited_curve",
			Description:   "If the Key is ECDSA, then the curve MUST be one of NIST P-256, P-384, or P-521",
			Citation:      "CABF CS BRs 6.1.5.2",
			Source:        lint.CABFCSBaselineRequirements,
			EffectiveDate: util.CABF_CS_BRs_1_2_Date,
		},
		Lint: NewCsEcdsaProhibitedCurve,
	})
}

type csEcdsaProhibitedCurve struct{}

func NewCsEcdsaProhibitedCurve() lint.CertificateLintInterface {
	return &csEcdsaProhibitedCurve{}
}

func (l *csEcdsaProhibitedCurve) CheckApplies(c *x509.Certificate) bool {
	return c.PublicKeyAlgorithm == x509.ECDSA
}

func (l *csEcdsaProhibitedCurve) Execute(c *x509.Certificate) *lint.LintResult {
	var key *ecdsa.PublicKey
	switch k := c.PublicKey.(type) {
	case *x509.AugmentedECDSA:
		key = k.Pub
	case *ecdsa.PublicKey:
		key = k
	default:
		return &lint.LintResult{Status: lint.NA}
	}

	switch key.Curve.Params().Name {
	case "P-256", "P-384", "P-521":
		return &lint.LintResult{Status: lint.Pass}
	default:
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "ECDSA key curve must be one of NIST P-256, P-384, or P-521",
		}
	}
}
