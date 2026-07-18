package cpcps

import (
	"fmt"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"github.com/letsencrypt/boulder/linter/lints"
)

type precertificateMatchesCPSProfile struct {
	// Config is filled from the shared [Global] stanza of the lint
	// configuration; see IssuingCAConfig.
	Config *SharedConfig
}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_precertificate_matches_cps_profile",
			Description:   "Let's Encrypt Precertificates are issued in accordance with the CP/CPS Profile",
			Citation:      "CPS: 7.1",
			Source:        lints.LetsEncryptCPS,
			EffectiveDate: lints.CPSV62Date,
		},
		Lint: NewPrecertificateMatchesCPSProfile,
	})
}

func NewPrecertificateMatchesCPSProfile() lint.CertificateLintInterface {
	return &precertificateMatchesCPSProfile{}
}

// Configure implements the lint.Configurable interface.
func (l *precertificateMatchesCPSProfile) Configure() any {
	return l
}

func (l *precertificateMatchesCPSProfile) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.IsServerAuthCert(c) && util.IsExtInCert(c, util.CtPoisonOID)
}

// Execute checks the given precertificate against the Precertificate Profile,
// which is "Identical to the Subscriber (Server) Certificate Profile, except
// that the SignedCertificateTimestampList extension is omitted, and a critical
// 'CT poison' extension (OID 1.3.6.1.4.1.11129.2.4.3) is included": first the
// rows shared with the Subscriber (Server) Certificate Profile (whose
// implementation lives in lint_subscriber_server_certificate.go), then the
// rows specific to precertificates.
// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1097-L1099
func (l *precertificateMatchesCPSProfile) Execute(c *x509.Certificate) *lint.LintResult {
	res := checkSubscriberProfile(c, l.Config.issuerPEM())
	if res != nil {
		return res
	}

	// In place of the SignedCertificateTimestampList extension, a critical
	// "CT poison" extension (OID 1.3.6.1.4.1.11129.2.4.3) is included.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1099
	poisonExt := getExtension(c, util.CtPoisonOID)
	if poisonExt == nil {
		return errResult("CT poison extension is not present")
	}
	if !poisonExt.Critical {
		return errResult("CT poison extension is not critical")
	}

	// Any other extension is "Not present". In particular, the
	// SignedCertificateTimestampList extension is omitted from
	// precertificates, so it is not in the allowed set.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1093
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1099
	allowedExtensions := []asn1.ObjectIdentifier{
		authorityInformationAccessOID,
		authorityKeyIdentifierOID,
		basicConstraintsOID,
		certificatePoliciesOID,
		crlDistributionPointsOID,
		extKeyUsageOID,
		keyUsageOID,
		util.CtPoisonOID,
		subjectAltNameOID,
		subjectKeyIdentifierOID,
	}
	for _, ext := range c.Extensions {
		found := false
		for _, oid := range allowedExtensions {
			if ext.Id.Equal(oid) {
				found = true
			}
		}
		if !found {
			return errResult(fmt.Sprintf("unexpected extension %s", ext.Id.String()))
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
