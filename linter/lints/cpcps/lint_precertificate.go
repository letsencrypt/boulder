package cpcps

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"github.com/letsencrypt/boulder/linter/lints"
)

type precertificateMatchesCPSProfile struct {
	// Config is filled from the shared [Global] stanza of the lint
	// configuration; see SharedConfig.
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

// Execute checks the given precertificate against the Precertificate Profile:
// first the rows shared with the Subscriber (Server) Certificate Profile
// (whose implementation lives in lint_subscriber_server_certificate.go), then
// the requirements specific to precertificates.
// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1097
// ### Precertificate Profile
func (l *precertificateMatchesCPSProfile) Execute(c *x509.Certificate) *lint.LintResult {
	res := checkSubscriberProfile(c, l.Config.issuerPEM())
	if res != nil {
		return res
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1099
	// Identical to the Subscriber (Server) Certificate Profile, except that the `SignedCertificateTimestampList` extension is omitted, and a critical "CT poison" extension (OID 1.3.6.1.4.1.11129.2.4.3) is included. ISRG Precertificates are issued directly by the Issuing CA, not by a delegated Precertificate Signing CA.
	// This check enforces the presence and criticality of the CT poison
	// extension.
	poisonExt := getExtension(c, util.CtPoisonOID)
	if poisonExt == nil {
		return errResult("CT poison extension is not present")
	}
	if !poisonExt.Critical {
		return errResult("CT poison extension is not critical")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1093
	// |         Any other extension              | Not present |
	// The SignedCertificateTimestampList extension is omitted from
	// precertificates and replaced by the CT poison extension, so the allowed
	// set here differs from the Subscriber (Server) Certificate Profile's by
	// exactly that substitution.
	extensions := map[string]bool{
		authorityInformationAccessOID.String(): false,
		authorityKeyIdentifierOID.String():     false,
		basicConstraintsOID.String():           false,
		certificatePoliciesOID.String():        false,
		crlDistributionPointsOID.String():      false,
		extKeyUsageOID.String():                false,
		keyUsageOID.String():                   false,
		util.CtPoisonOID.String():              false,
		subjectAltNameOID.String():             false,
		subjectKeyIdentifierOID.String():       false,
	}
	for _, ext := range c.Extensions {
		seen, allowed := extensions[ext.Id.String()]
		if !allowed {
			return errResult(fmt.Sprintf("unexpected extension %s", ext.Id.String()))
		}
		if seen {
			return errResult(fmt.Sprintf("duplicate extension %s", ext.Id.String()))
		}
		extensions[ext.Id.String()] = true
	}
	for oid, seen := range extensions {
		// The subjectKeyIdentifier extension is optional, so missing it is ok.
		if !seen && oid != subjectKeyIdentifierOID.String() {
			return errResult(fmt.Sprintf("missing extension %s", oid))
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
