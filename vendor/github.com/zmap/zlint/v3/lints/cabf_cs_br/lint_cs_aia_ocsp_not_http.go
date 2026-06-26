package cabf_cs_br

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/*7.1.2.3 a. authorityInformationAccess
If the CA provides OCSP responses, it MUST contain the HTTP URL of the Issuing
CA's OCSP responder (accessMethod = 1.3.6.1.5.5.7.48.1).*/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cs_aia_ocsp_not_http",
			Description:   "If the CA provides OCSP responses, the authorityInformationAccess extension MUST contain the HTTP URL of the Issuing CA's OCSP responder (id-ad-ocsp).",
			Citation:      "CABF CS BRs 7.1.2.3.a",
			Source:        lint.CABFCSBaselineRequirements,
			EffectiveDate: util.CABF_CS_BRs_1_2_Date,
		},
		Lint: NewCsAiaOcspNotHttp,
	})
}

type csAiaOcspNotHttp struct{}

func NewCsAiaOcspNotHttp() lint.LintInterface {
	return &csAiaOcspNotHttp{}
}

func (l *csAiaOcspNotHttp) CheckApplies(c *x509.Certificate) bool {
	return (util.IsSubscriberCert(c) || util.IsSubCA(c)) && len(c.OCSPServer) > 0
}

func (l *csAiaOcspNotHttp) Execute(c *x509.Certificate) *lint.LintResult {
	for _, u := range c.OCSPServer {
		purl, err := url.Parse(u)
		if err != nil {
			return &lint.LintResult{Status: lint.Error, Details: "Could not parse OCSP URL in AIA."}
		}
		if !strings.EqualFold(purl.Scheme, "http") {
			return &lint.LintResult{Status: lint.Error, Details: fmt.Sprintf("Found scheme %s in OCSP URL of AIA, which is not allowed.", purl.Scheme)}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
