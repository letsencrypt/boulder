package cpcps

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"

	"github.com/letsencrypt/boulder/linter/lints"
)

type crlMatchesExactlyOneCPSProfile struct{}

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_crl_matches_exactly_one_cps_profile",
			Description:   "All ISRG CRLs are issued in accordance with one of the following CRL Profiles",
			Citation:      "CPS: 7.2",
			Source:        lints.LetsEncryptCPS,
			EffectiveDate: lints.CPSV63Date,
		},
		Lint: NewCRLMatchesExactlyOneCPSProfile,
	})
}

func NewCRLMatchesExactlyOneCPSProfile() lint.RevocationListLintInterface {
	return &crlMatchesExactlyOneCPSProfile{}
}

func (l *crlMatchesExactlyOneCPSProfile) CheckApplies(c *x509.RevocationList) bool {
	// This lint applies to *all* CRLs, and checks what kind of CRL they are in
	// Execute.
	return true
}

// Execute checks that the given CRL meets the "CheckApplies" criteria of
// exactly one of the two lints which enforce each of our CP/CPS CRL profiles.
// https://github.com/letsencrypt/cp-cps/blob/v6.3/CP-CPS.md?plain=1#L1159
// All ISRG CRLs are issued in accordance with one of the following CRL Profiles. ISRG does not issue any CRLs whose scope includes both CA and Subscriber Certificates.
func (l *crlMatchesExactlyOneCPSProfile) Execute(c *x509.RevocationList) *lint.LintResult {
	onlyContainsUserCerts, onlyContainsCACerts := getCRLScope(c)
	matches := 0

	// This condition must exactly match the condition in
	// caCRLMatchesCPSProfile.CheckApplies().
	if onlyContainsCACerts {
		matches++
	}

	// This condition must exactly match the condition in
	// subscriberCRLMatchesCPSProfile.CheckApplies().
	if onlyContainsUserCerts {
		matches++
	}

	if matches < 1 {
		return errResult("CRL does not match any CPS profile")
	}

	if matches > 1 {
		return errResult("CRL matches multiple CPS profiles")
	}

	return &lint.LintResult{Status: lint.Pass}
}
