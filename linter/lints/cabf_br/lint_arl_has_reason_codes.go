package cabfbr

import (
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/letsencrypt/boulder/linter/lints"
)

type arlHasReasonCodes struct{}

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_arl_has_reason_codes",
			Description:   "The reasonCode MUST be present for revoked Subordinate CA Certificates",
			Citation:      "BRs 7.2.2; CCADB 3.2; Microsoft 2.1.7",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_2_0_0_Date,
		},
		Lint: NewArlHasReasonCodes,
	})
}

func NewArlHasReasonCodes() lint.RevocationListLintInterface {
	return &arlHasReasonCodes{}
}

func (l *arlHasReasonCodes) CheckApplies(c *x509.RevocationList) bool {
	// This requirement applies only to ARLs, i.e. CRLs which contain entries for
	// Subordinate CA Certificates. Assume that any CRL which does *not* have the
	// onlyContainsUserCerts bit set is potentially an ARL. Note that this is a
	// much stricter criterion than some CAs might want: it would be reasonable to
	// only enforce this lint on CRLs which *do* have the onlyContainsCACerts bit
	// set. But since we guarantee that all of our CRLs have exactly one of those
	// two bits set, it's better to cast our net wider here, just in case.

	// Extract the Issuing Distribution Point extension, which contains the bools
	// that attest whether this CRL covers CA certs or not.
	idpOID := asn1.ObjectIdentifier{2, 5, 29, 28} // id-ce-issuingDistributionPoint
	idpe := lints.GetExtWithOID(c.Extensions, idpOID)
	if idpe == nil {
		return true
	}

	idpv := cryptobyte.String(idpe.Value)
	if !idpv.ReadASN1(&idpv, cryptobyte_asn1.SEQUENCE) {
		return true
	}

	// Skip the distribution point itself.
	ok := idpv.SkipOptionalASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed())
	if !ok {
		return true
	}

	// Read the onlyContainsUserCerts boolean from the extension.
	var onlyContainsUserCerts bool
	ok = lints.ReadOptionalASN1BooleanWithTag(&idpv, &onlyContainsUserCerts, cryptobyte_asn1.Tag(1).ContextSpecific(), false)
	if !ok {
		return true
	}

	// A CRL which only contains end-entity certs is exempt from this lint, all
	// others are potentially in violation.
	if onlyContainsUserCerts {
		return false
	}
	return true
}

func (l *arlHasReasonCodes) Execute(c *x509.RevocationList) *lint.LintResult {
	for _, rc := range c.RevokedCertificates {
		if rc.ReasonCode == nil {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "For any revoked subordinate CA certificate, each corresponding revocation entry published to a CRL MUST include a reasonCode extension.",
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
