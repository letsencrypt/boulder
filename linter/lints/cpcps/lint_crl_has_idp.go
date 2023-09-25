package cpcps

import (
	"net/url"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/letsencrypt/boulder/linter/lints"
)

type crlHasIDP struct{}

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
			Name:          "e_crl_has_idp",
			Description:   "Let's Encrypt CRLs must have the Issuing Distribution Point extension with appropriate contents",
			Citation:      "",
			Source:        lints.LetsEncryptCPS,
			EffectiveDate: lints.CPSV33Date,
		},
		Lint: NewCrlHasIDP,
	})
}

func NewCrlHasIDP() lint.RevocationListLintInterface {
	return &crlHasIDP{}
}

func (l *crlHasIDP) CheckApplies(c *x509.RevocationList) bool {
	return true
}

func (l *crlHasIDP) Execute(c *x509.RevocationList) *lint.LintResult {
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
	// its constituent fields, DistributionPoint and OnlyContainsUserCerts.
	idpv := cryptobyte.String(idpe.Value)
	if !idpv.ReadASN1(&idpv, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{
			Status:  lint.Warn,
			Details: "Failed to read issuingDistributionPoint",
		}
	}

	// We read these booleans as a byte and ensure the value is 0xFF because
	// cryptobyte.ReadASN1Boolean can't handle the custom encoding rules for the
	// [1] and [2] tagged fields referenced above. X.690 (07/2002) section 8.2
	// states that a boolean set to true will have contents FF.
	// https://www.itu.int/rec/T-REC-X.690-200207-S/en
	onlyContainsUserCerts := make([]byte, 0)
	onlyContainsCACerts := make([]byte, 0)

	// Ensure that the distributionPoint is a reasonable URI. To get to the URI,
	// we have to step inside the DistributionPointName, then step inside that's
	// FullName, and finally read the singular SEQUENCE OF GeneralName element.
	if idpv.PeekASN1Tag(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) || idpv.PeekASN1Tag(cryptobyte_asn1.Tag(1).ContextSpecific()) {
		var dpName cryptobyte.String
		if !idpv.ReadASN1(&dpName, cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) {
			return &lint.LintResult{
				Status:  lint.Warn,
				Details: "Failed to read IDP distributionPoint",
			}
		}
		if !dpName.ReadASN1(&dpName, cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) {
			return &lint.LintResult{
				Status:  lint.Warn,
				Details: "Failed to read IDP distributionPoint fullName",
			}
		}

		uriBytes := make([]byte, 0)
		if !dpName.ReadASN1Bytes(&uriBytes, cryptobyte_asn1.Tag(6).ContextSpecific()) {
			return &lint.LintResult{
				Status:  lint.Warn,
				Details: "Failed to read IDP URI",
			}
		}

		uri, err := url.Parse(string(uriBytes))
		if err != nil {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "Failed to parse IDP URI",
			}
		}
		if uri.Scheme != "http" {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "IDP URI MUST use http scheme",
			}
		}
		if !dpName.Empty() {
			return &lint.LintResult{
				Status:  lint.Warn,
				Details: "IDP should contain only one distributionPoint",
			}
		}
		if !idpv.ReadASN1Bytes(&onlyContainsUserCerts, cryptobyte_asn1.Tag(1).ContextSpecific()) {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "Failed to read IDP onlyContainsUserCerts",
			}
		}
		if len(onlyContainsUserCerts) != 1 || onlyContainsUserCerts[0] != 0xFF {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "IDP should set onlyContainsUserCerts: TRUE",
			}
		}
	}

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

	if len(onlyContainsUserCerts) == 1 && len(onlyContainsCACerts) == 1 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "IDP should set either onlyContainsUserCerts or onlyContainsCACerts to TRUE, not both",
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
