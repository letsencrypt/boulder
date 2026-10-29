package cpcps

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/letsencrypt/boulder/linter/lints"
)

type caCRLMatchesCPSProfile struct {
	// Config is filled from the shared [Global] stanza of the lint
	// configuration; see SharedConfig.
	Config *SharedConfig
}

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_ca_crl_matches_cps_profile",
			Description:   "Let's Encrypt CA CRLs are issued in accordance with the CP/CPS Profile",
			Citation:      "CPS: 7.2",
			Source:        lints.LetsEncryptCPS,
			EffectiveDate: lints.CPSV63Date,
		},
		Lint: NewCACRLMatchesCPSProfile,
	})
}

func NewCACRLMatchesCPSProfile() lint.RevocationListLintInterface {
	return &caCRLMatchesCPSProfile{}
}

// Configure implements the lint.Configurable interface.
func (l *caCRLMatchesCPSProfile) Configure() any {
	return l
}

func (l *caCRLMatchesCPSProfile) CheckApplies(c *x509.RevocationList) bool {
	// This condition must exactly match the condition in
	// crlMatchesExactlyOneCPSProfile.Execute().
	_, onlyContainsCACerts := getCRLScope(c)
	return onlyContainsCACerts
}

// Execute checks the given CRL against the CA CRL Profile.
// https://github.com/letsencrypt/cp-cps/blob/v6.3/CP-CPS.md?plain=1#L1161
// ### CA CRL Profile
func (l *caCRLMatchesCPSProfile) Execute(c *x509.RevocationList) *lint.LintResult {
	// Several rows of the profile require byte-for-byte correspondence with
	// the Issuing CA's certificate, so this lint must be configured with it.
	issuer, err := parseConfiguredCertificate(l.Config.issuerPEM())
	if err != nil {
		return fatalResult(err.Error())
	}
	if issuer == nil {
		return fatalResult("lint has not been configured with the Issuing CA's certificate (issuer_certificate)")
	}

	// https://github.com/letsencrypt/cp-cps/blob/v6.3/CP-CPS.md?plain=1#L1168
	// |     `version`                          | X.509 v2 (integer value 1) |
	tbs := cryptobyte.String(c.RawTBSRevocationList)
	var tbsCertList cryptobyte.String
	if !tbs.ReadASN1(&tbsCertList, cryptobyte_asn1.SEQUENCE) {
		return errResult("failed to parse tbsCertList")
	}
	var version int
	if tbsCertList.PeekASN1Tag(cryptobyte_asn1.INTEGER) && !tbsCertList.ReadASN1Integer(&version) {
		return errResult("failed to parse tbsCertList.version")
	}
	if version != 1 {
		return errResult("version is not v2")
	}

	// https://github.com/letsencrypt/cp-cps/blob/v6.3/CP-CPS.md?plain=1#L1169
	// |     `signature`                        | See [Section 7.1.3.2](#7132-signature-algorithmidentifier) |
	// Section 7.1.3.2 requires signature AlgorithmIdentifiers to be
	// byte-for-byte identical with one of the hexadecimal encodings specified
	// by Section 7.1.3.2 of the Baseline Requirements.
	var tbsSignature cryptobyte.String
	if !tbsCertList.ReadASN1Element(&tbsSignature, cryptobyte_asn1.SEQUENCE) {
		return errResult("failed to parse tbsCertList.signature")
	}
	if !brSignatureAlgorithmIdentifiers[hex.EncodeToString(tbsSignature)] {
		return errResult("signature is not byte-for-byte identical to a BRs Section 7.1.3.2 encoding")
	}

	// https://github.com/letsencrypt/cp-cps/blob/v6.3/CP-CPS.md?plain=1#L1170
	// |     `issuer`                           | Byte-for-byte identical to the `subject` field of the Issuing CA |
	if !bytes.Equal(c.RawIssuer, issuer.RawSubject) {
		return errResult("issuer is not byte-for-byte identical to the subject of the configured Issuing CA")
	}

	// https://github.com/letsencrypt/cp-cps/blob/v6.3/CP-CPS.md?plain=1#L1171
	// |     `thisUpdate`                       | The date and time at which the CRL validity begins |
	// Nothing to check here, since zcrypto refuses to parse a CRL without a
	// thisUpdate, and our CPS places no restrictions on the field.

	// https://github.com/letsencrypt/cp-cps/blob/v6.3/CP-CPS.md?plain=1#L1172
	// |     `nextUpdate`                       | At most 365 days after the `thisUpdate` |
	if c.NextUpdate.IsZero() {
		return errResult("nextUpdate is not present")
	}
	if c.NextUpdate.Before(c.ThisUpdate) {
		return errResult("nextUpdate is before thisUpdate")
	}
	if c.NextUpdate.Sub(c.ThisUpdate) > 365*lints.BRDay {
		// Note that we don't need the off-by-one-second math here, because CRL
		// validity intervals are not measured the same way as cert validity periods.
		return errResult("nextUpdate is more than 365 days after thisUpdate")
	}

	// https://github.com/letsencrypt/cp-cps/blob/v6.3/CP-CPS.md?plain=1#L1173
	// |     `revokedCertificates`              | Present if and only if there is at least one revoked certificate entry |
	// A nil slice represents the field being omitted.
	if c.RevokedCertificates != nil && len(c.RevokedCertificates) == 0 {
		return errResult("revokedCertificates is present but contains no entries")
	}
	for _, rc := range c.RevokedCertificates {
		// https://github.com/letsencrypt/cp-cps/blob/v6.3/CP-CPS.md?plain=1#L1174
		// |         `serialNumber`                 | Byte-for-byte identical to the `serialNumber` of the revoked Certificate |
		// We can't test correspondence here, so we instead run the same serial
		// number checks that the certificate linters run.
		if rc.SerialNumber == nil || rc.SerialNumber.Sign() <= 0 {
			return errResult(fmt.Sprintf("entry %x: serialNumber is not a positive integer", rc.SerialNumber))
		}
		if rc.SerialNumber.BitLen() <= 100 {
			return errResult(fmt.Sprintf("entry %x: serialNumber is not more than 100 bits long", rc.SerialNumber))
		}

		// https://github.com/letsencrypt/cp-cps/blob/v6.3/CP-CPS.md?plain=1#L1175
		// |         `revocationDate`               | The date and time at which ISRG recorded the Certificate as revoked, no later than `thisUpdate` |
		if rc.RevocationTime.After(c.ThisUpdate) {
			return errResult(fmt.Sprintf("entry %x: revocationDate is later than thisUpdate", rc.SerialNumber))
		}

		// https://github.com/letsencrypt/cp-cps/blob/v6.3/CP-CPS.md?plain=1#L1177
		// |              `reasonCode`              | Contains the most appropriate revocation reason code from among 1, 4, 5, or 9 |
		reasonCodeExt := lints.GetExtWithOID(rc.Extensions, util.ReasonCodeOID)
		if reasonCodeExt == nil || rc.ReasonCode == nil {
			return errResult(fmt.Sprintf("entry %x: reasonCode extension is not present", rc.SerialNumber))
		}
		if reasonCodeExt.Critical {
			return errResult(fmt.Sprintf("entry %x: reasonCode extension is critical", rc.SerialNumber))
		}
		switch *rc.ReasonCode {
		case 1, 4, 5, 9:
		default:
			return errResult(fmt.Sprintf("entry %x: reasonCode %d is not one of 1, 4, 5, or 9", rc.SerialNumber, *rc.ReasonCode))
		}

		// https://github.com/letsencrypt/cp-cps/blob/v6.3/CP-CPS.md?plain=1#L1178
		// |              Any other extension       | Not present |
		entryExtensions := map[string]bool{
			util.ReasonCodeOID.String(): false,
		}
		for _, ext := range rc.Extensions {
			seen, ok := entryExtensions[ext.Id.String()]
			if !ok {
				return errResult(fmt.Sprintf("entry %x: unexpected extension %s", rc.SerialNumber, ext.Id.String()))
			}
			if seen {
				return errResult(fmt.Sprintf("entry %x: duplicate extension %s", rc.SerialNumber, ext.Id.String()))
			}
			entryExtensions[ext.Id.String()] = true
		}
		for oid, seen := range entryExtensions {
			if !seen {
				return errResult(fmt.Sprintf("entry %x: missing extension %s", rc.SerialNumber, oid))
			}
		}
	}

	// https://github.com/letsencrypt/cp-cps/blob/v6.3/CP-CPS.md?plain=1#L1180
	// |         `authorityKeyIdentifier`       | Contains a `keyIdentifier` byte-for-byte identical to the `subjectKeyIdentifier` of the Issuing CA |
	akidExt := lints.GetExtWithOID(c.Extensions, util.AuthkeyOID)
	if akidExt == nil {
		return errResult("authorityKeyIdentifier extension is not present")
	}
	if akidExt.Critical {
		return errResult("authorityKeyIdentifier extension is critical")
	}
	akidValue := cryptobyte.String(akidExt.Value)
	var akid cryptobyte.String
	if !akidValue.ReadASN1(&akid, cryptobyte_asn1.SEQUENCE) || !akidValue.Empty() {
		return errResult("failed to parse authorityKeyIdentifier")
	}
	var keyID cryptobyte.String
	if !akid.ReadOptionalASN1(&keyID, nil, cryptobyte_asn1.Tag(0).ContextSpecific()) {
		return errResult("failed to parse authorityKeyIdentifier keyIdentifier")
	}
	if len(keyID) == 0 {
		return errResult("authorityKeyIdentifier does not contain a keyIdentifier")
	}
	if !bytes.Equal(keyID, issuer.SubjectKeyId) {
		return errResult("authorityKeyIdentifier keyIdentifier is not byte-for-byte identical to the subjectKeyIdentifier of the configured Issuing CA")
	}

	// https://github.com/letsencrypt/cp-cps/blob/v6.3/CP-CPS.md?plain=1#L1181
	// |         `CRLNumber`                    | Contains a strictly-increasing positive integer less than 2^159 |
	crlNumberExt := lints.GetExtWithOID(c.Extensions, util.CRLNumberOID)
	if crlNumberExt == nil {
		return errResult("CRLNumber extension is not present")
	}
	if crlNumberExt.Critical {
		return errResult("CRLNumber extension is critical")
	}
	if c.Number == nil || c.Number.Sign() <= 0 {
		return errResult("CRLNumber is not a positive integer")
	}
	if c.Number.Cmp(new(big.Int).Lsh(big.NewInt(1), 159)) >= 0 {
		return errResult("CRLNumber is not less than 2^159")
	}

	// https://github.com/letsencrypt/cp-cps/blob/v6.3/CP-CPS.md?plain=1#L1182
	// |         `issuingDistributionPoint`     | Critical, with only `onlyContainsCACerts` set to true |
	idpExt := lints.GetExtWithOID(c.Extensions, issuingDistributionPointOID)
	if idpExt == nil {
		return errResult("issuingDistributionPoint extension is not present")
	}
	if !idpExt.Critical {
		return errResult("issuingDistributionPoint extension is not critical")
	}
	idpValue := cryptobyte.String(idpExt.Value)
	var idp cryptobyte.String
	if !idpValue.ReadASN1(&idp, cryptobyte_asn1.SEQUENCE) || !idpValue.Empty() {
		return errResult("failed to parse issuingDistributionPoint")
	}
	if idp.PeekASN1Tag(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) {
		return errResult("issuingDistributionPoint distributionPoint is present")
	}
	if idp.PeekASN1Tag(cryptobyte_asn1.Tag(1).ContextSpecific()) {
		return errResult("issuingDistributionPoint onlyContainsUserCerts is present")
	}
	var onlyContainsCACerts cryptobyte.String
	if !idp.ReadASN1(&onlyContainsCACerts, cryptobyte_asn1.Tag(2).ContextSpecific()) || !bytes.Equal(onlyContainsCACerts, []byte{0xFF}) {
		return errResult("issuingDistributionPoint onlyContainsCACerts is not set to true")
	}
	if !idp.Empty() {
		return errResult("issuingDistributionPoint contains fields other than onlyContainsCACerts")
	}

	// https://github.com/letsencrypt/cp-cps/blob/v6.3/CP-CPS.md?plain=1#L1183
	// |         Any other extension            | Not present |
	extensions := map[string]bool{
		util.AuthkeyOID.String():             false,
		util.CRLNumberOID.String():           false,
		issuingDistributionPointOID.String(): false,
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
		if !seen {
			return errResult(fmt.Sprintf("missing extension %s", oid))
		}
	}

	// https://github.com/letsencrypt/cp-cps/blob/v6.3/CP-CPS.md?plain=1#L1184
	// | `signatureAlgorithm`                   | Byte-for-byte identical to the `tbsCertList.signature` |
	signatureAlgorithm, err := getOuterSignatureAlgorithm(c.Raw)
	if err != nil {
		return errResult("failed to parse signatureAlgorithm")
	}
	if !bytes.Equal(tbsSignature, signatureAlgorithm) {
		return errResult("signatureAlgorithm is not byte-for-byte identical to the tbsCertList.signature")
	}

	// https://github.com/letsencrypt/cp-cps/blob/v6.3/CP-CPS.md?plain=1#L1185
	// | `signatureValue`                       | A signature appropriate to the `signatureAlgorithm` field |
	// We can't verify the signature here: pre-issuance linting operates on a
	// CRL signed by a throwaway key.

	return &lint.LintResult{Status: lint.Pass}
}
