package cpcps

import (
	"net/url"

	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zlint/v3/lint"
	"golang.org/x/crypto/cryptobyte"
)

// checkIDP checks that the CRL does have an Issuing Distribution Point, that it
// is critical, that it contains a single http distributionPointName, that it
// asserts the onlyContainsUserCerts boolean, and that it does not contain any
// of the other fields. (RFC 5280, Section 5.2.5).
func checkIDP(crl *crl_x509.RevocationList) *lint.LintResult {
	idpOID := asn1.ObjectIdentifier{2, 5, 29, 28} // id-ce-issuingDistributionPoint
	idpe := getExtWithOID(crl.Extensions, idpOID)
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

	// Ensure that the DistributionPoint is a reasonable URI. To get to the URI,
	// we have to step inside the DistributionPointName, then step inside that's
	// FullName, and finally read the singular SEQUENCE OF GeneralName element.
	if !idpv.PeekASN1Tag(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) {
		return &lint.LintResult{
			Status:  lint.Warn,
			Details: "IDP should contain distributionPoint",
		}
	}

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

	// Ensure that OnlyContainsUserCerts is True. We have to read this boolean as
	// a byte and ensure its value is 0xFF because cryptobyte.ReadASN1Boolean
	// can't handle custom encoding rules like this field's [1] tag.
	if !idpv.PeekASN1Tag(cryptobyte_asn1.Tag(1).ContextSpecific()) {
		return &lint.LintResult{
			Status:  lint.Warn,
			Details: "IDP should contain onlyContainsUserCerts",
		}
	}

	onlyContainsUserCerts := make([]byte, 0)
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

	// Ensure that no other fields are set.
	if !idpv.Empty() {
		return &lint.LintResult{
			Status:  lint.Warn,
			Details: "IDP should not contain fields other than distributionPoint and onlyContainsUserCerts",
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
