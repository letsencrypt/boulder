package cpcps

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"github.com/letsencrypt/boulder/linter/lints"
)

type certMatchesExactlyOneCPSProfile struct {
	// Config is filled from the shared [Global] stanza of the lint
	// configuration; see SharedConfig.
	Config *SharedConfig
}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cert_matches_exactly_one_cps_profile",
			Description:   "All ISRG Certificates are issued in accordance with one of the following Certificate Profiles",
			Citation:      "CPS: 7.1",
			Source:        lints.LetsEncryptCPS,
			EffectiveDate: lints.CPSV62Date,
		},
		Lint: NewCertMatchesExactlyOneCPSProfile,
	})
}

func NewCertMatchesExactlyOneCPSProfile() lint.CertificateLintInterface {
	return &certMatchesExactlyOneCPSProfile{}
}

// Configure implements the lint.Configurable interface.
func (l *certMatchesExactlyOneCPSProfile) Configure() any {
	return l
}

func (l *certMatchesExactlyOneCPSProfile) CheckApplies(c *x509.Certificate) bool {
	// This lint applies to *all* certs, and checks what kind of cert they are
	// in Execute.
	return true
}

// Execute checks that the given certificate meets the "CheckApplies" criteria
// of exactly one of the five lints which enforce each of our CP/CPS profiles.
// https://github.com/letsencrypt/cp-cps/blob/v6.2/CP-CPS.md?plain=1#L1003
// All ISRG Certificates are issued in accordance with one of the following Certificate Profiles, which are derived from the profiles with the same names found in Section 7.1.2 of the Baseline Requirements.
func (l *certMatchesExactlyOneCPSProfile) Execute(c *x509.Certificate) *lint.LintResult {
	matches := 0

	// This condition must exactly match the condition in
	// rootCACertificateMatchesCPSProfile.CheckApplies().
	if util.IsRootCA(c) {
		matches++
	}

	// This condition must exactly match the condition in
	// tlsSubordinateCACertificateMatchesCPSProfile.CheckApplies().
	if util.IsSubCA(c) && len(l.Config.existingPEM()) == 0 {
		matches++
	}

	// This condition must exactly match the condition in
	// crossCertifiedSubordinateCACertificateMatchesCPSProfile.CheckApplies().
	if util.IsSubCA(c) && len(l.Config.existingPEM()) > 0 {
		matches++
	}

	// This condition must exactly match the condition in
	// subscriberServerCertificateMatchesCPSProfile.CheckApplies().
	if util.IsSubscriberCert(c) && util.IsServerAuthCert(c) && !util.IsExtInCert(c, util.CtPoisonOID) {
		matches++
	}

	// This condition must exactly match the condition in
	// precertificateMatchesCPSProfile.CheckApplies().
	if util.IsSubscriberCert(c) && util.IsServerAuthCert(c) && util.IsExtInCert(c, util.CtPoisonOID) {
		matches++
	}

	if matches < 1 {
		return errResult("cert does not match any CPS profile")
	}

	if matches > 1 {
		return errResult("cert matches multiple CPS profiles")
	}

	return &lint.LintResult{Status: lint.Pass}
}
