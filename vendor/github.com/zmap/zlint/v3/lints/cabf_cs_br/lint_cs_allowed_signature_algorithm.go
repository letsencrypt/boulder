package cabf_cs_br

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/*7.1.3.2.1 RSA
The CA SHALL use one of the following signature algorithms:
    RSASSA-PKCS1-v1_5 with SHA-256
    RSASSA-PKCS1-v1_5 with SHA-384
    RSASSA-PKCS1-v1_5 with SHA-512
    RSASSA-PSS with SHA-256
    RSASSA-PSS with SHA-384
    RSASSA-PSS with SHA-512

In addition, the CA MAY use RSASSA-PKCS1-v1_5 with SHA-1 if one of the following conditions are met:
    It is used within Timestamp Authority Certificate and the date of the notBefore field is not greater than 2022-04-30; or,
    It is used within an OCSP response; or,
    It is used within a CRL; or,
    It is used within a Timestamp Token and the date of the genTime field is not greater than 2022-04-30.

7.1.3.2.2 ECDSA
The CA SHALL use one of the following signature algorithms:
    ECDSA with SHA-256
    ECDSA with SHA-384
    ECDSA with SHA-512

7.1.3.2.3 DSA
The CA SHALL use the following signature algorithm:
    DSA with SHA-256

In addition, the CA MAY use DSA with SHA-1 if one of the following conditions are met:
    It is used within Timestamp Authority Certificate and the date of the notBefore field is not greater than 2022-04-30; or,
    It is used within an OCSP response; or,
    It is used within a CRL; or,
    It is used within a Timestamp Token and the date of the genTime field is not greater than 2022-04-30.
*/

var (
	passSigAlgs = map[x509.SignatureAlgorithm]bool{
		x509.SHA256WithRSAPSS: true,
		x509.SHA384WithRSAPSS: true,
		x509.SHA512WithRSAPSS: true,
		x509.SHA256WithRSA:    true,
		x509.SHA384WithRSA:    true,
		x509.SHA512WithRSA:    true,
		x509.ECDSAWithSHA256:  true,
		x509.ECDSAWithSHA384:  true,
		x509.ECDSAWithSHA512:  true,
		x509.DSAWithSHA256:    true,
	}
)

type csSignatureAlgorithmNotSupported struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cs_signature_algorithm_not_supported",
			Description:   "Certificates MUST meet the following requirements for algorithm Source: SHA-1*, SHA-256, SHA-384, SHA-512",
			Citation:      "CABF CS BRs 7.1.3.2",
			Source:        lint.CABFCSBaselineRequirements,
			EffectiveDate: util.CABF_CS_BRs_1_2_Date,
		},
		Lint: NewCsSignatureAlgorithmNotSupported,
	})
}

func NewCsSignatureAlgorithmNotSupported() lint.CertificateLintInterface {
	return &csSignatureAlgorithmNotSupported{}
}

func (l *csSignatureAlgorithmNotSupported) CheckApplies(c *x509.Certificate) bool {
	return true
}

func (l *csSignatureAlgorithmNotSupported) Execute(c *x509.Certificate) *lint.LintResult {
	sigAlg := c.SignatureAlgorithm
	status := lint.Error
	if passSigAlgs[sigAlg] {
		status = lint.Pass
	}
	return &lint.LintResult{
		Status: status,
	}
}
