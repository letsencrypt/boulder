package cabfbr

import (
	"fmt"
	"time"

	"github.com/letsencrypt/boulder/linter/lints"
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
	"golang.org/x/crypto/cryptobyte"

	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type crlValidityPeriod struct{}

/************************************************
Baseline Requirements, Section 4.9.7:
* For the status of Subscriber Certificates [...] the value of the nextUpdate
  field MUST NOT be more than ten days beyond the value of the thisUpdate field.
* For the status of Subordinate CA Certificates [...]. The value of the
  nextUpdate field MUST NOT be more than twelve months beyond the value of the
  thisUpdatefield.
************************************************/

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_crl_validity_period",
			Description:   "Let's Encrypt CRLs must have an acceptable validity period",
			Citation:      "BRs: 4.9.7",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_1_2_1_Date,
		},
		Lint: NewCrlValidityPeriod,
	})
}

func NewCrlValidityPeriod() lint.RevocationListLintInterface {
	return &crlValidityPeriod{}
}

func (l *crlValidityPeriod) CheckApplies(c *x509.RevocationList) bool {
	return true
}

func (l *crlValidityPeriod) Execute(c *x509.RevocationList) *lint.LintResult {
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

	// The only way to determine which type of CRL we're dealing with, the
	// issuingDistributionPoint must be parsed and the internal fields
	// inspected.
	idpOID := asn1.ObjectIdentifier{2, 5, 29, 28} // id-ce-issuingDistributionPoint
	idpe := lints.GetExtWithOID(c.Extensions, idpOID)
	if idpe == nil {
		return &lint.LintResult{
			Status:  lint.Warn,
			Details: "CRL missing IDP",
		}
	}

	// Step inside the outer issuingDistributionPoint sequence to get access to
	// its constituent fields.
	idpv := cryptobyte.String(idpe.Value)
	_ = idpv.ReadASN1(&idpv, cryptobyte_asn1.SEQUENCE)

	// We read this boolean as a byte and ensure its value is 0xFF because
	// cryptobyte.ReadASN1Boolean can't handle the custom encoding rules for the
	// [1] and [2] tagged fields referenced above. For the purposes of this
	// lint, we just need to know if the field exists.
	onlyContainsCACerts := make([]byte, 0)

	// Default to subscriber cert CRL.
	var BRValidity = 10 * 24 * time.Hour
	var validityString = "10 days"

	if idpv.PeekASN1Tag(cryptobyte_asn1.Tag(2).ContextSpecific()) {
		if idpv.ReadASN1Bytes(&onlyContainsCACerts, cryptobyte_asn1.Tag(2).ContextSpecific()) {
			if len(onlyContainsCACerts) == 1 && onlyContainsCACerts[0] == 0xFF {
				BRValidity = 365 * lints.BRDay
				validityString = "365 days"
			}
		}
	}

	parsedValidity := c.NextUpdate.Sub(c.ThisUpdate)
	if parsedValidity <= 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRL has NextUpdate at or before ThisUpdate",
		}
	}

	if parsedValidity > BRValidity {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("CRL has validity period greater than %s", validityString),
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
