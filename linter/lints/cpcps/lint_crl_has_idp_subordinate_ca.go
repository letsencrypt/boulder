package cpcps

import (
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/letsencrypt/boulder/linter/lints"
)

type crlHasIDPSubordinateCA struct{}

/************************************************
Various root programs (and the BRs, after Ballot SC-063 passes) require that
sharded/partitioned CRLs have a specifically-encoded Issuing Distribution Point
extension. Since there's no way to tell from the CRL itself whether or not it
is sharded, we apply this lint universally to all CRLs, but as part of the Let's
Encrypt-specific suite of lints.
************************************************/

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_crl_has_idp_subordinate_ca",
			Description:   "Let's Encrypt Subordinate CA CRLs must have the onlyContainsCACerts boolean set to true",
			Citation:      "",
			Source:        lints.LetsEncryptCPS,
			EffectiveDate: lints.CPSV33Date,
		},
		Lint: NewCrlHasIDPSubordinateCA,
	})
}

func NewCrlHasIDPSubordinateCA() lint.RevocationListLintInterface {
	return &crlHasIDPSubordinateCA{}
}

func (l *crlHasIDPSubordinateCA) CheckApplies(c *x509.RevocationList) bool {
	return true
}

func (l *crlHasIDPSubordinateCA) Execute(c *x509.RevocationList) *lint.LintResult {
	idpOID := asn1.ObjectIdentifier{2, 5, 29, 28} // id-ce-issuingDistributionPoint
	idpe := lints.GetExtWithOID(c.Extensions, idpOID)
	if idpe == nil {
		return &lint.LintResult{
			Status:  lint.Warn,
			Details: "CRL missing IDP",
		}
	}
	if !idpe.Critical {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "IDP MUST be critical",
		}
	}
	// Step inside the outer issuingDistributionPoint sequence to get access to
	// its constituent field - OnlyContainsCACerts.
	idpv := cryptobyte.String(idpe.Value)
	if !idpv.ReadASN1(&idpv, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{
			Status:  lint.Warn,
			Details: "Failed to read issuingDistributionPoint",
		}
	}

	/*
		Let's Encrypt issues CRLs for two distinct purposes:
		   1) CRLs containing subscriber certificates created by the
		      crl-updater. These CRLs must have only the distributionPoint and
		      onlyContainsUserCerts fields set.
		   2) CRLs containing subordinate CA certificates created by the
		      ceremony tool. These CRLs must only have the onlyContainsCACerts
		      field set.

		RFC 5280 Section 5.2.5

		IssuingDistributionPoint ::= SEQUENCE {
			distributionPoint          [0] DistributionPointName OPTIONAL,
			onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
			onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
			...
		}
	*/

	// We read this boolean as a byte and ensure its value is 0xFF because
	// cryptobyte.ReadASN1Boolean can't handle the custom encoding rules for the
	// [2] tagged field referenced above.
	onlyContainsCACerts := make([]byte, 0)

	if idpv.PeekASN1Tag(cryptobyte_asn1.Tag(2).ContextSpecific()) {
		if !idpv.ReadASN1Bytes(&onlyContainsCACerts, cryptobyte_asn1.Tag(2).ContextSpecific()) {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "Failed to read IDP onlyContainsCACerts",
			}
		}
		if len(onlyContainsCACerts) != 1 || onlyContainsCACerts[0] != 0xFF {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "IDP should set onlyContainsCACerts: TRUE",
			}
		}
	}

	// Ensure that no other fields are set.
	if !idpv.Empty() {
		return &lint.LintResult{
			Status:  lint.Warn,
			Details: "Unexpected IDP fields were found",
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
