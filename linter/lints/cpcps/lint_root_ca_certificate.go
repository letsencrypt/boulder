package cpcps

import (
	"bytes"
	"crypto/ecdh"
	"crypto/elliptic"
	stdx509 "crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	zrsa "github.com/zmap/zcrypto/rsa"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/linter/lints"
)

type rootCACertificateMatchesCPSProfile struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_root_ca_certificate_matches_cps_profile",
			Description:   "Let's Encrypt Root CA Certificates are issued in accordance with the CP/CPS Profile",
			Citation:      "CPS: 7.1",
			Source:        lints.LetsEncryptCPS,
			EffectiveDate: lints.CPSV62Date,
		},
		Lint: NewRootCACertificateMatchesCPSProfile,
	})
}

func NewRootCACertificateMatchesCPSProfile() lint.CertificateLintInterface {
	return &rootCACertificateMatchesCPSProfile{}
}

func (l *rootCACertificateMatchesCPSProfile) CheckApplies(c *x509.Certificate) bool {
	return util.IsRootCA(c)
}

// Execute checks the given certificate against the Root CA Certificate
// Profile, row by row. Root CA Certificates are self-signed, so unlike the
// other profiles there is no Issuing CA to be configured with: the issuer
// correspondence is checked against the certificate's own subject.
// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L992
// ### Root CA Certificate Profile
func (l *rootCACertificateMatchesCPSProfile) Execute(c *x509.Certificate) *lint.LintResult {
	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L997
	// |     `version`                  | See [Section 7.1.1](#711-version-numbers) |
	// Section 7.1.1 says "All certificates use X.509 version 3".
	if c.Version != 3 {
		return errResult("version is not v3")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L998
	// |     `serialNumber`             | More than 100 bits of output from a CSPRNG, optionally with additional non-random bits |
	// We can't test randomness here, but a serial containing more than 100
	// bits of CSPRNG output must itself be more than 100 bits long.
	if c.SerialNumber == nil || c.SerialNumber.Sign() <= 0 {
		return errResult("serialNumber is not a positive integer")
	}
	if c.SerialNumber.BitLen() <= 100 {
		return errResult("serialNumber is not more than 100 bits long")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L999
	// |     `signature`                | See [Section 7.1.3.2](#7132-signature-algorithmidentifier) |
	// Section 7.1.3.2 requires signature AlgorithmIdentifiers to be
	// byte-for-byte identical with one of the hexadecimal encodings specified
	// by Section 7.1.3.2 of the Baseline Requirements.
	tbsSignature, err := util.GetSignatureAlgorithmInTBSEncoded(c)
	if err != nil {
		return errResult("failed to parse tbsCertificate.signature")
	}
	if !brSignatureAlgorithmIdentifiers[hex.EncodeToString(tbsSignature)] {
		return errResult("signature is not byte-for-byte identical to a BRs Section 7.1.3.2 encoding")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1000
	// |     `issuer`                   | Byte-for-byte identical to the `subject` field |
	if !bytes.Equal(c.RawIssuer, c.RawSubject) {
		return errResult("issuer is not byte-for-byte identical to the subject")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1001
	// |     `validity`                 | At most 3660 days (approx. 10 years) |
	// RFC 5280 4.1.2.5: "The validity period for a certificate is the period
	// of time from notBefore through notAfter, inclusive."
	if c.NotAfter.Before(c.NotBefore) {
		return errResult("validity is negative: notAfter is before notBefore")
	}
	if c.NotAfter.Add(time.Second).Sub(c.NotBefore) > 3660*lints.BRDay {
		return errResult("validity is more than 3660 days")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1002
	// |     `subject`                  | C=US, O=ISRG, and a unique CN |
	// We can't test for CN uniqueness here, but the rest we can check.
	if len(c.Subject.Names) != 3 {
		return errResult("subject does not contain exactly C, O, and CN attributes")
	}
	if len(c.Subject.Country) != 1 || c.Subject.Country[0] != "US" {
		return errResult("subject countryName is not US")
	}
	if len(c.Subject.Organization) != 1 || c.Subject.Organization[0] != "ISRG" {
		return errResult("subject organizationName is not ISRG")
	}
	if c.Subject.CommonName == "" {
		return errResult("subject commonName is empty")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1003
	// |     `subjectPublicKeyInfo`     | See Sections [6.1.5](#615-key-sizes), [6.1.6](#616-public-key-parameters-generation-and-quality-checking), and [7.1.3.1](#7131-subjectpublickeyinfo) |
	// Section 6.1.5 says Root CA key pairs are "either RSA keys whose encoded
	// modulus size is 4096 bits, or ECDSA keys which are a valid point on the
	// NIST P-384 elliptic curve". Section 6.1.6 requires the key parameter
	// quality checks performed inline below. Section 7.1.3.1 requires the
	// AlgorithmIdentifier to be byte-for-byte identical to a BRs Section
	// 7.1.3.1 encoding. Point-on-curve validation is also performed by
	// zcrypto at parse time.
	spkiAlgID, err := util.GetPublicKeyAidEncoded(c)
	if err != nil {
		return errResult("failed to parse subjectPublicKeyInfo algorithm")
	}
	switch key := c.PublicKey.(type) {
	case *zrsa.PublicKey:
		// DER INTEGERs are minimal-length, so the encoded modulus size is its
		// bit length rounded up to a whole number of octets.
		encodedModulusBits := len(key.N.Bytes()) * 8
		if encodedModulusBits != 4096 {
			return errResult(fmt.Sprintf("RSA encoded modulus size %d is not allowed", encodedModulusBits))
		}
		if hex.EncodeToString(spkiAlgID) != spkiAlgorithmRSA {
			return errResult("public key algorithm is not byte-for-byte identical to the BRs Section 7.1.3.1 RSA encoding")
		}
		// Section 6.1.6, via NIST SP 800-89 Section 5.3.3, requires that RSA
		// keys have "a public exponent of 65537 and an odd modulus which has
		// no factors smaller than 752".
		// https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-89.pdf
		if key.E.Cmp(big.NewInt(65537)) != 0 {
			return errResult(fmt.Sprintf("RSA public exponent %s is not 65537", key.E))
		}
		if key.N.Bit(0) == 0 {
			return errResult("RSA modulus is even")
		}
		if new(big.Int).GCD(nil, nil, key.N, smallOddPrimesProduct).Cmp(big.NewInt(1)) != 0 {
			return errResult("RSA modulus has a prime factor smaller than 752")
		}
	case *x509.AugmentedECDSA:
		if key.Pub.Curve != elliptic.P384() {
			return errResult(fmt.Sprintf("ECDSA curve %s is not allowed", key.Pub.Curve.Params().Name))
		}
		if hex.EncodeToString(spkiAlgID) != spkiAlgorithmP384 {
			return errResult("public key algorithm is not byte-for-byte identical to the BRs Section 7.1.3.1 encoding for its curve")
		}
		// Section 6.1.6, via NIST SP 800-56A (Revision 2) Section 5.6.2.3.2,
		// requires that ECDSA keys comply with the ECC Full Public Key
		// Validation Routine. ecdh.Curve.NewPublicKey accepts only a
		// well-formed uncompressed point which is on the curve, within the
		// underlying field, and not the point at infinity; the routine's
		// final step, confirming the point's order, is implied by the others
		// for the NIST curves, whose cofactors are 1.
		// https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-56ar2.pdf
		_, err = ecdh.P384().NewPublicKey(key.Raw.Bytes)
		if err != nil {
			return errResult("ECDSA public key is not a valid uncompressed point on its curve")
		}
	default:
		return errResult(fmt.Sprintf("unsupported public key type %T", c.PublicKey))
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1004
	// |     `issuerUniqueID`           | Not present |
	if c.IssuerUniqueId.Bytes != nil {
		return errResult("issuerUniqueID is present")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1005
	// |     `subjectUniqueID`          | Not present |
	if c.SubjectUniqueId.Bytes != nil {
		return errResult("subjectUniqueID is present")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1007
	// |         `basicConstraints`     | Critical, with `cA` set to true |
	bcExt := getExtension(c, basicConstraintsOID)
	if bcExt == nil {
		return errResult("basicConstraints extension is not present")
	}
	if !bcExt.Critical {
		return errResult("basicConstraints extension is not critical")
	}
	if !c.IsCA {
		return errResult("basicConstraints cA is not true")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1008
	// |         `keyUsage`             | Critical, with only the `keyCertSign` (5) and `cRLSign` (6) bits set |
	kuExt := getExtension(c, keyUsageOID)
	if kuExt == nil {
		return errResult("keyUsage extension is not present")
	}
	if !kuExt.Critical {
		return errResult("keyUsage extension is not critical")
	}
	if c.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		return errResult("keyUsage does not assert exactly the bits required by the profile")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1009
	// |         `subjectKeyIdentifier` | Contains a truncated hash of the `subjectPublicKey`, per Section 2(1) of RFC 7093 |
	skidExt := getExtension(c, subjectKeyIdentifierOID)
	if skidExt == nil {
		return errResult("subjectKeyIdentifier extension is not present")
	}
	if skidExt.Critical {
		return errResult("subjectKeyIdentifier extension is critical")
	}
	subjectPublicKey, err := stdx509.ParsePKIXPublicKey(c.RawSubjectPublicKeyInfo)
	if err != nil {
		return errResult("failed to parse subjectPublicKey")
	}
	// core.GenerateSKID implements the RFC 7093 Section 2(1) method.
	expectedSKID, err := core.GenerateSKID(subjectPublicKey)
	if err != nil {
		return errResult("failed to compute subjectKeyIdentifier from the subjectPublicKey")
	}
	if !bytes.Equal(c.SubjectKeyId, expectedSKID) {
		return errResult("subjectKeyIdentifier is not the RFC 7093 Section 2(1) truncated hash of the subjectPublicKey")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1010
	// |         Any other extension    | Not present |
	extensions := map[string]bool{
		basicConstraintsOID.String():     false,
		keyUsageOID.String():             false,
		subjectKeyIdentifierOID.String(): false,
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

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1011
	// | `signatureAlgorithm`           | Byte-for-byte identical to the `tbsCertificate.signature` |
	signatureAlgorithm, err := getOuterSignatureAlgorithm(c.Raw)
	if err != nil {
		return errResult(err.Error())
	}
	if !bytes.Equal(tbsSignature, signatureAlgorithm) {
		return errResult("signatureAlgorithm is not byte-for-byte identical to the tbsCertificate.signature")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1012
	// | `signatureValue`               | A signature appropriate to the `signatureAlgorithm` field |
	// We can't verify the signature under pre-issuance linting (the
	// certificate is signed by a throwaway key), but CheckApplies only
	// selects certificates whose self-signature zcrypto has verified.

	return &lint.LintResult{Status: lint.Pass}
}
