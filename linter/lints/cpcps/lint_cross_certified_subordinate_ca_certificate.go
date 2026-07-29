package cpcps

import (
	"bytes"
	"crypto/ecdh"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/weppos/publicsuffix-go/publicsuffix"
	zrsa "github.com/zmap/zcrypto/rsa"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"github.com/letsencrypt/boulder/linter/lints"
)

type crossCertifiedSubordinateCACertificateMatchesCPSProfile struct {
	// Config is filled from the shared [Global] stanza of the lint
	// configuration; see SharedConfig.
	Config *SharedConfig
}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cross_certified_subordinate_ca_certificate_matches_cps_profile",
			Description:   "Let's Encrypt Cross-Certified Subordinate CA Certificates are issued in accordance with the CP/CPS Profile",
			Citation:      "CPS: 7.1",
			Source:        lints.LetsEncryptCPS,
			EffectiveDate: lints.CPSV62Date,
		},
		Lint: NewCrossCertifiedSubordinateCACertificateMatchesCPSProfile,
	})
}

func NewCrossCertifiedSubordinateCACertificateMatchesCPSProfile() lint.CertificateLintInterface {
	return &crossCertifiedSubordinateCACertificateMatchesCPSProfile{}
}

// Configure implements the lint.Configurable interface.
func (l *crossCertifiedSubordinateCACertificateMatchesCPSProfile) Configure() any {
	return l
}

func (l *crossCertifiedSubordinateCACertificateMatchesCPSProfile) CheckApplies(c *x509.Certificate) bool {
	// If an existing cert is configured, then we assume this is a cross-sign.
	// This condition must exactly match the condition in
	// certMatchesExactlyOneCPSProfile.Execute().
	return util.IsSubCA(c) && len(l.Config.existingPEM()) > 0
}

// Execute checks the given certificate against the Cross-Certified Subordinate
// CA Certificate Profile, row by row.
// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1014
// ### Cross-Certified Subordinate CA Certificate Profile
func (l *crossCertifiedSubordinateCACertificateMatchesCPSProfile) Execute(c *x509.Certificate) *lint.LintResult {
	// Several rows of the profile require byte-for-byte correspondence with
	// the Issuing CA's certificate or with the existing CA Certificate being
	// cross-signed, so this lint must be configured with both.
	issuer, err := parseConfiguredCertificate(l.Config.issuerPEM())
	if err != nil {
		return fatalResult(err.Error())
	}
	if issuer == nil {
		return fatalResult("lint has not been configured with the Issuing CA's certificate (issuer_certificate)")
	}
	existing, err := parseConfiguredCertificate(l.Config.existingPEM())
	if err != nil {
		return fatalResult(err.Error())
	}
	if existing == nil {
		return fatalResult("lint has not been configured with the existing CA Certificate being cross-signed (existing_certificate)")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1019
	// |     `version`                        | See [Section 7.1.1](#711-version-numbers) |
	// Section 7.1.1 says "All certificates use X.509 version 3".
	if c.Version != 3 {
		return errResult("version is not v3")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1020
	// |     `serialNumber`                   | More than 100 bits of output from a CSPRNG, optionally with additional non-random bits |
	// We can't test randomness here, but a serial containing more than 100
	// bits of CSPRNG output must itself be more than 100 bits long.
	if c.SerialNumber == nil || c.SerialNumber.Sign() <= 0 {
		return errResult("serialNumber is not a positive integer")
	}
	if c.SerialNumber.BitLen() <= 100 {
		return errResult("serialNumber is not more than 100 bits long")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1021
	// |     `signature`                      | See [Section 7.1.3.2](#7132-signature-algorithmidentifier) |
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

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1022
	// |     `issuer`                         | Byte-for-byte identical to the `subject` field of the Issuing CA |
	if !bytes.Equal(c.RawIssuer, issuer.RawSubject) {
		return errResult("issuer is not byte-for-byte identical to the subject of the configured Issuing CA")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1023
	// |     `validity`                       | At most 1098 days (approx. 3 years) |
	// RFC 5280 4.1.2.5: "The validity period for a certificate is the period
	// of time from notBefore through notAfter, inclusive."
	if c.NotAfter.Before(c.NotBefore) {
		return errResult("validity is negative: notAfter is before notBefore")
	}
	if c.NotAfter.Add(time.Second).Sub(c.NotBefore) > 1098*lints.BRDay {
		return errResult("validity is more than 1098 days")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1024
	// |     `subject`                        | Byte-for-byte identical to the `subject` field of the existing CA Certificate |
	if !bytes.Equal(c.RawSubject, existing.RawSubject) {
		return errResult("subject is not byte-for-byte identical to the subject of the configured existing CA Certificate")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1025
	// |     `subjectPublicKeyInfo`           | Byte-for-byte identical to the `subjectPublicKeyInfo` field of the existing CA Certificate. See also Sections [6.1.5](#615-key-sizes), [6.1.6](#616-public-key-parameters-generation-and-quality-checking), and [7.1.3.1](#7131-subjectpublickeyinfo) |
	if !bytes.Equal(c.RawSubjectPublicKeyInfo, existing.RawSubjectPublicKeyInfo) {
		return errResult("subjectPublicKeyInfo is not byte-for-byte identical to that of the configured existing CA Certificate")
	}
	// The existing CA Certificate may be either a Root or a Subordinate, so the
	// checks below allow both sets of key sizes allowed by Section 6.1.5: RSA
	// keys whose encoded modulus size is 4096 bits (Root CA) or 2048 bits
	// (Subordinate CA), or ECDSA keys which are a valid point on the NIST P-384
	// elliptic curve. Section 6.1.6 requires the key parameter quality checks
	// performed inline below. Section 7.1.3.1 requires the AlgorithmIdentifier to
	// be byte-for-byte identical to a BRs Section 7.1.3.1 encoding.
	// Point-on-curve validation is also performed by zcrypto at parse time.
	spkiAlgID, err := util.GetPublicKeyAidEncoded(c)
	if err != nil {
		return errResult("failed to parse subjectPublicKeyInfo algorithm")
	}
	switch key := c.PublicKey.(type) {
	case *zrsa.PublicKey:
		// DER INTEGERs are minimal-length, so the encoded modulus size is its
		// bit length rounded up to a whole number of octets.
		encodedModulusBits := len(key.N.Bytes()) * 8
		if encodedModulusBits != 2048 && encodedModulusBits != 4096 {
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

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1026
	// |     `issuerUniqueID`                 | Not present |
	if c.IssuerUniqueId.Bytes != nil {
		return errResult("issuerUniqueID is present")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1027
	// |     `subjectUniqueID`                | Not present |
	if c.SubjectUniqueId.Bytes != nil {
		return errResult("subjectUniqueID is present")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1029
	// |         `authorityInformationAccess` | Contains the HTTP URI of the Issuing CA's Certificate |
	// Whether the URI actually serves the Issuing CA's certificate is not
	// observable here, but the extension must contain exactly one caIssuers
	// entry with an http URI and nothing else (in particular, no OCSP
	// entries).
	aiaExt := getExtension(c, util.AiaOID)
	if aiaExt == nil {
		return errResult("authorityInformationAccess extension is not present")
	}
	if aiaExt.Critical {
		return errResult("authorityInformationAccess extension is critical")
	}
	if len(c.OCSPServer) != 0 {
		return errResult("authorityInformationAccess contains an OCSP entry")
	}
	if len(c.IssuingCertificateURL) != 1 {
		return errResult("authorityInformationAccess does not contain exactly one caIssuers entry")
	}
	aiaURL, err := url.Parse(c.IssuingCertificateURL[0])
	if err != nil || aiaURL.Scheme != "http" {
		return errResult("authorityInformationAccess caIssuers URI is not an http URL")
	}
	_, err = publicsuffix.ParseFromListWithOptions(publicsuffix.DefaultList, aiaURL.Hostname(), &publicsuffix.FindOptions{IgnorePrivate: true, DefaultRule: nil})
	if err != nil {
		return errResult("authorityInformationAccess caIssuers URI hostname is not a domain under a public suffix")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1030
	// |         `authorityKeyIdentifier`     | Contains a `keyIdentifier` byte-for-byte identical to the `subjectKeyIdentifier` of the Issuing CA |
	akidExt := getExtension(c, util.AuthkeyOID)
	if akidExt == nil {
		return errResult("authorityKeyIdentifier extension is not present")
	}
	if akidExt.Critical {
		return errResult("authorityKeyIdentifier extension is critical")
	}
	if len(c.AuthorityKeyId) == 0 {
		return errResult("authorityKeyIdentifier does not contain a keyIdentifier")
	}
	if !bytes.Equal(c.AuthorityKeyId, issuer.SubjectKeyId) {
		return errResult("authorityKeyIdentifier keyIdentifier is not byte-for-byte identical to the subjectKeyIdentifier of the configured Issuing CA")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1031
	// |         `basicConstraints`           | Critical, with `cA` set to true and `pathLenConstraint` identical to the existing CA Certificate |
	bcExt := getExtension(c, util.BasicConstOID)
	if bcExt == nil {
		return errResult("basicConstraints extension is not present")
	}
	if !bcExt.Critical {
		return errResult("basicConstraints extension is not critical")
	}
	if !c.IsCA {
		return errResult("basicConstraints cA is not true")
	}
	if c.MaxPathLen != existing.MaxPathLen || c.MaxPathLenZero != existing.MaxPathLenZero {
		return errResult("basicConstraints pathLenConstraint is not identical to that of the configured existing CA Certificate")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1032
	// |         `certificatePolicies`        | Contains only the Baseline Requirements Domain Validated Reserved Policy Identifier (OID 2.23.140.1.2.1) |
	cpExt := getExtension(c, util.CertPolicyOID)
	if cpExt == nil {
		return errResult("certificatePolicies extension is not present")
	}
	if cpExt.Critical {
		return errResult("certificatePolicies extension is critical")
	}
	if len(c.PolicyIdentifiers) != 1 || !c.PolicyIdentifiers[0].Equal(util.BRDomainValidatedOID) {
		return errResult("certificatePolicies does not contain exactly the Domain Validated Reserved Policy Identifier")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1033
	// |         `crlDistributionPoints`      | Contains the HTTP URI of a CRL issued by the Issuing CA whose scope includes this certificate |
	// Whether the CRL's scope actually includes this certificate is not
	// observable here.
	crldpExt := getExtension(c, util.CrlDistOID)
	if crldpExt == nil {
		return errResult("crlDistributionPoints extension is not present")
	}
	if crldpExt.Critical {
		return errResult("crlDistributionPoints extension is critical")
	}
	if len(c.CRLDistributionPoints) != 1 {
		return errResult("crlDistributionPoints does not contain exactly one distribution point")
	}
	crldpURL, err := url.Parse(c.CRLDistributionPoints[0])
	if err != nil || crldpURL.Scheme != "http" {
		return errResult("crlDistributionPoints URI is not an http URL")
	}
	_, err = publicsuffix.ParseFromListWithOptions(publicsuffix.DefaultList, crldpURL.Hostname(), &publicsuffix.FindOptions{IgnorePrivate: true, DefaultRule: nil})
	if err != nil {
		return errResult("crlDistributionPoints URI hostname is not a domain under a public suffix")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1034
	// |         `extKeyUsage`                | Contains only `id-kp-serverAuth` (OID 1.3.6.1.5.5.7.3.1) |
	ekuExt := getExtension(c, util.EkuSynOid)
	if ekuExt == nil {
		return errResult("extKeyUsage extension is not present")
	}
	if ekuExt.Critical {
		return errResult("extKeyUsage extension is critical")
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(c.UnknownExtKeyUsage) != 0 {
		return errResult("extKeyUsage does not contain exactly id-kp-serverAuth")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1035
	// |         `keyUsage`                   | Critical, with only the `keyCertSign` (5) and `cRLSign` (6) bits set |
	kuExt := getExtension(c, util.KeyUsageOID)
	if kuExt == nil {
		return errResult("keyUsage extension is not present")
	}
	if !kuExt.Critical {
		return errResult("keyUsage extension is not critical")
	}
	if c.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		return errResult("keyUsage does not assert exactly the bits required by the profile")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1036
	// |         `subjectKeyIdentifier`       | Byte-for-byte identical to the `subjectKeyIdentifier` of the existing CA Certificate |
	// Unlike the other profiles we cannot assume the RFC 7093 construction
	// here, because the existing CA Certificate's subjectKeyIdentifier may
	// have been computed by any method.
	skidExt := getExtension(c, util.SubjectKeyIdentityOID)
	if skidExt == nil {
		return errResult("subjectKeyIdentifier extension is not present")
	}
	if skidExt.Critical {
		return errResult("subjectKeyIdentifier extension is critical")
	}
	if len(c.SubjectKeyId) == 0 {
		return errResult("subjectKeyIdentifier is empty")
	}
	if !bytes.Equal(c.SubjectKeyId, existing.SubjectKeyId) {
		return errResult("subjectKeyIdentifier is not byte-for-byte identical to that of the configured existing CA Certificate")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1037
	// |         Any other extension          | Not present |
	extensions := map[string]bool{
		util.AiaOID.String():                false,
		util.AuthkeyOID.String():            false,
		util.BasicConstOID.String():         false,
		util.CertPolicyOID.String():         false,
		util.CrlDistOID.String():            false,
		util.EkuSynOid.String():             false,
		util.KeyUsageOID.String():           false,
		util.SubjectKeyIdentityOID.String(): false,
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

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1038
	// | `signatureAlgorithm`                 | Byte-for-byte identical to the `tbsCertificate.signature` |
	signatureAlgorithm, err := getOuterSignatureAlgorithm(c.Raw)
	if err != nil {
		return errResult(err.Error())
	}
	if !bytes.Equal(tbsSignature, signatureAlgorithm) {
		return errResult("signatureAlgorithm is not byte-for-byte identical to the tbsCertificate.signature")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1039
	// | `signatureValue`                     | A signature appropriate to the `signatureAlgorithm` field |
	// We can't verify the signature here: pre-issuance linting operates on a
	// certificate signed by a throwaway key.

	return &lint.LintResult{Status: lint.Pass}
}
