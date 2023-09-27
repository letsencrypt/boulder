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
	// its constituent fields: distributionPoint [0],
	// onlyContainsUserCerts [1], and onlyContainsCACerts [2].
	idpv := cryptobyte.String(idpe.Value)
	if !idpv.ReadASN1(&idpv, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{
			Status:  lint.Warn,
			Details: "Failed to read issuingDistributionPoint",
		}
	}

	distributionPointTag := cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()
	// Though this value looks the same as distributionPointTag, it's important
	// to note it's technically retrieving data nested within another tag and
	// this can help understand the hierarchy.
	distributionPointFullNameTag := cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()
	onlyContainsUserCertsTag := cryptobyte_asn1.Tag(1).ContextSpecific()
	onlyContainsCACertsTag := cryptobyte_asn1.Tag(2).ContextSpecific()
	distributionPointURITag := cryptobyte_asn1.Tag(6).ContextSpecific()

	if idpv.PeekASN1Tag(distributionPointTag) || idpv.PeekASN1Tag(onlyContainsUserCertsTag) {
		// If either the distributionPoint [0] field or the
		// onlyContainsUserCerts [1] field is present, assume we're dealing with
		// a CRL containing Subscriber Certs.

		var dpName cryptobyte.String
		if !idpv.ReadASN1(&dpName, distributionPointTag) {
			return &lint.LintResult{
				Status:  lint.Warn,
				Details: "Failed to read IDP distributionPoint",
			}
		}
		if !dpName.ReadASN1(&dpName, distributionPointFullNameTag) {
			return &lint.LintResult{
				Status:  lint.Warn,
				Details: "Failed to read IDP distributionPoint fullName",
			}
		}

		var uriBytes []byte
		if !dpName.ReadASN1Bytes(&uriBytes, distributionPointURITag) {
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

		ok, boolPresent := lints.ReadOptionalASN1BooleanWithTag(&idpv, onlyContainsUserCertsTag)
		if !ok {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "Failed to read IDP onlyContainsUserCerts",
			}
		}
		if !boolPresent {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "IDP should set onlyContainsUserCerts: TRUE",
			}
		}
	} else {
		// If neither the distributionPoint [0] or onlyContainsUserCerts [1]
		// fields are present, assume that we're dealing with a CRL containing
		// CA Certs. Therefore, check that it contains the onlyContainsCACerts
		// [2] field.

		ok, boolPresent := lints.ReadOptionalASN1BooleanWithTag(&idpv, onlyContainsCACertsTag)
		if !ok {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "Failed to read IDP onlyContainsCACerts",
			}
		}
		if !boolPresent {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "IDP should set onlyContainsCACerts: TRUE",
			}
		}
	}

	// Ensure that no other fields are set.
	if !idpv.Empty() {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Unexpected IDP fields were found",
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
