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
	*/

	idpOID := asn1.ObjectIdentifier{2, 5, 29, 28} // id-ce-issuingDistributionPoint
	idpe := lints.GetExtWithOID(c.Extensions, idpOID)
	if idpe == nil {
		return &lint.LintResult{
			Status:  lint.Warn,
			Details: "CRL missing IssuingDistributionPoint",
		}
	}
	if !idpe.Critical {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "IssuingDistributionPoint MUST be critical",
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

	var dpName cryptobyte.String
	var distributionPointExists bool
	distributionPointTag := cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()
	if !idpv.ReadOptionalASN1(&dpName, &distributionPointExists, distributionPointTag) {
		return &lint.LintResult{
			Status:  lint.Warn,
			Details: "Failed to read IssuingDistributionPoint distributionPoint",
		}
	}

	idp := lints.NewIssuingDistributionPoint()
	if distributionPointExists {
		lintErr := parseSingleDistributionPointName(&dpName, idp)
		if lintErr != nil {
			return lintErr
		}
	}

	onlyContainsUserCertsTag := cryptobyte_asn1.Tag(1).ContextSpecific()
	if !lints.ReadOptionalASN1BooleanWithTag(&idpv, &idp.OnlyContainsUserCerts, onlyContainsUserCertsTag, false) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Failed to read IssuingDistributionPoint onlyContainsUserCerts",
		}
	}

	onlyContainsCACertsTag := cryptobyte_asn1.Tag(2).ContextSpecific()
	if !lints.ReadOptionalASN1BooleanWithTag(&idpv, &idp.OnlyContainsCACerts, onlyContainsCACertsTag, false) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Failed to read IssuingDistributionPoint onlyContainsCACerts",
		}
	}

	if !idpv.Empty() {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Unexpected IssuingDistributionPoint fields were found",
		}
	}

	if idp.OnlyContainsUserCerts {
		if idp.OnlyContainsCACerts {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "IssuingDistributionPoint should not have both onlyContainsUserCerts: TRUE and onlyContainsCACerts: TRUE",
			}
		}
		if idp.DistributionPointURI == nil {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "IssuingDistributionPoint should have both DistributionPointName and onlyContainsUserCerts: TRUE",
			}
		}
	} else if idp.OnlyContainsCACerts {
		if idp.DistributionPointURI != nil {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "IssuingDistributionPoint should not have both DistributionPointName and onlyContainsCACerts: TRUE",
			}
		}
	} else {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Neither onlyContainsUserCerts nor onlyContainsCACerts was set",
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}

// parseSingleDistributionPointName examines the provided distributionPointName
// and updates idp with the URI if it is found. The distribution point name is
// checked for validity and returns a non-nil LintResult if there were any
// problems.
func parseSingleDistributionPointName(distributionPointName *cryptobyte.String, idp *lints.IssuingDistributionPoint) *lint.LintResult {
	fullNameTag := cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()
	if !distributionPointName.ReadASN1(distributionPointName, fullNameTag) {
		return &lint.LintResult{
			Status:  lint.Warn,
			Details: "Failed to read IssuingDistributionPoint distributionPoint fullName",
		}
	}

	var uriBytes []byte
	uriTag := cryptobyte_asn1.Tag(6).ContextSpecific()
	if !distributionPointName.ReadASN1Bytes(&uriBytes, uriTag) {
		return &lint.LintResult{
			Status:  lint.Warn,
			Details: "Failed to read IssuingDistributionPoint URI",
		}
	}
	var err error
	idp.DistributionPointURI, err = url.Parse(string(uriBytes))
	if err != nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Failed to parse IssuingDistributionPoint URI",
		}
	}
	if idp.DistributionPointURI.Scheme != "http" {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "IssuingDistributionPoint URI MUST use http scheme",
		}
	}
	if !distributionPointName.Empty() {
		return &lint.LintResult{
			Status:  lint.Warn,
			Details: "IssuingDistributionPoint should contain only one distributionPoint",
		}
	}

	return nil
}
