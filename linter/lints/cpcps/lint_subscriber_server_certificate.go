package cpcps

import (
	"bytes"
	"crypto/ecdh"
	"crypto/elliptic"
	stdx509 "crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"slices"
	"time"

	"github.com/weppos/publicsuffix-go/publicsuffix"
	zrsa "github.com/zmap/zcrypto/rsa"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/ct"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/linter/lints"
)

type subscriberServerCertificateMatchesCPSProfile struct {
	// Config is filled from the shared [Global] stanza of the lint
	// configuration; see SharedConfig.
	Config *SharedConfig
}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_subscriber_server_certificate_matches_cps_profile",
			Description:   "Let's Encrypt Subscriber Server Certificates are issued in accordance with the CP/CPS Profile",
			Citation:      "CPS: 7.1",
			Source:        lints.LetsEncryptCPS,
			EffectiveDate: lints.CPSV62Date,
		},
		Lint: NewSubscriberServerCertificateMatchesCPSProfile,
	})
}

func NewSubscriberServerCertificateMatchesCPSProfile() lint.CertificateLintInterface {
	return &subscriberServerCertificateMatchesCPSProfile{}
}

// Configure implements the lint.Configurable interface.
func (l *subscriberServerCertificateMatchesCPSProfile) Configure() any {
	return l
}

func (l *subscriberServerCertificateMatchesCPSProfile) CheckApplies(c *x509.Certificate) bool {
	// Precertificates are covered by the Precertificate Profile instead.
	return util.IsSubscriberCert(c) && util.IsServerAuthCert(c) && !util.IsExtInCert(c, util.CtPoisonOID)
}

// Execute checks the given certificate against the Subscriber (Server)
// Certificate Profile: first the rows shared with the Precertificate Profile,
// then the rows specific to final certificates.
// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1068
// ### Subscriber (Server) Certificate Profile
func (l *subscriberServerCertificateMatchesCPSProfile) Execute(c *x509.Certificate) *lint.LintResult {
	res := checkSubscriberProfile(c, l.Config.issuerPEM())
	if res != nil {
		return res
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1090
	// |         `SignedCertificateTimestampList` | Contains at least two SCTs from logs run by different operators |
	// We can't map log IDs to operators here, but SCTs from different
	// operators necessarily come from different logs, so we can check that at
	// least two distinct logs are present.
	sctExt := getExtension(c, sctListOID)
	if sctExt == nil {
		return errResult("signedCertificateTimestampList extension is not present")
	}
	if sctExt.Critical {
		return errResult("signedCertificateTimestampList extension is critical")
	}
	logIDs := make(map[ct.SHA256Hash]bool)
	for _, sct := range c.SignedCertificateTimestampList {
		logIDs[sct.LogID] = true
	}
	if len(logIDs) < 2 {
		return errResult("signedCertificateTimestampList does not contain SCTs from at least two distinct logs")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1093
	// |         Any other extension              | Not present |
	extensions := map[string]bool{
		authorityInformationAccessOID.String(): false,
		authorityKeyIdentifierOID.String():     false,
		basicConstraintsOID.String():           false,
		certificatePoliciesOID.String():        false,
		crlDistributionPointsOID.String():      false,
		extKeyUsageOID.String():                false,
		keyUsageOID.String():                   false,
		sctListOID.String():                    false,
		subjectAltNameOID.String():             false,
		subjectKeyIdentifierOID.String():       false,
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
		// The subjectKeyIdentifier extension is optional, so missing it is ok.
		if !seen && oid != subjectKeyIdentifierOID.String() {
			return errResult(fmt.Sprintf("missing extension %s", oid))
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// checkSubscriberProfile enforces the profile rows shared by the Subscriber
// (Server) Certificate Profile and the Precertificate Profile, which per
// CP/CPS Section 7.1 is "Identical to the Subscriber (Server) Certificate
// Profile, except that the SignedCertificateTimestampList extension is
// omitted, and a critical 'CT poison' extension (OID 1.3.6.1.4.1.11129.2.4.3)
// is included". It returns nil if every shared row passes; the rows which
// differ between the two profiles (SignedCertificateTimestampList or CT
// poison, and the set of permitted extensions) are checked by each lint's
// Execute method.
// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1068
// ### Subscriber (Server) Certificate Profile
func checkSubscriberProfile(c *x509.Certificate, issuerPEM string) *lint.LintResult {
	// Several rows of the profile require byte-for-byte correspondence with
	// the Issuing CA's certificate, so this lint must be configured with it.
	issuer, err := parseConfiguredCertificate(issuerPEM)
	if err != nil {
		return fatalResult(err.Error())
	}
	if issuer == nil {
		return fatalResult("lint has not been configured with the Issuing CA's certificate (issuer_certificate)")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1073
	// |     `version`                            | See [Section 7.1.1](#711-version-numbers) |
	// Section 7.1.1 says "All certificates use X.509 version 3".
	if c.Version != 3 {
		return errResult("version is not v3")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1074
	// |     `serialNumber`                       | More than 100 bits of output from a CSPRNG, optionally with additional non-random bits |
	// We can't test randomness here, but a serial containing more than 100
	// bits of CSPRNG output must itself be more than 100 bits long.
	if c.SerialNumber == nil || c.SerialNumber.Sign() <= 0 {
		return errResult("serialNumber is not a positive integer")
	}
	if c.SerialNumber.BitLen() <= 100 {
		return errResult("serialNumber is not more than 100 bits long")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1075
	// |     `signature`                          | See [Section 7.1.3.2](#7132-signature-algorithmidentifier) |
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

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1076
	// |     `issuer`                             | Byte-for-byte identical to the `subject` field of the Issuing CA |
	if !bytes.Equal(c.RawIssuer, issuer.RawSubject) {
		return errResult("issuer is not byte-for-byte identical to the subject of the configured Issuing CA")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1077
	// |     `validity`                           | At most 100 days |
	// RFC 5280 4.1.2.5: "The validity period for a certificate is the period
	// of time from notBefore through notAfter, inclusive."
	if c.NotAfter.Before(c.NotBefore) {
		return errResult("validity is negative: notAfter is before notBefore")
	}
	if c.NotAfter.Add(time.Second).Sub(c.NotBefore) > 100*lints.BRDay {
		return errResult("validity is more than 100 days")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1078
	// |     `subject`                            | CN omitted, or optionally contains one of the values from the Subject Alternative Name extension |
	for _, atv := range c.Subject.Names {
		if !atv.Type.Equal(commonNameOID) {
			return errResult(fmt.Sprintf("subject contains an attribute other than commonName: %s", atv.Type.String()))
		}
		cn, ok := atv.Value.(string)
		if !ok {
			return errResult("subject commonName value is not a string")
		}
		cnIP := net.ParseIP(cn)
		if cnIP != nil {
			found := false
			for _, ip := range c.IPAddresses {
				if ip.Equal(cnIP) {
					found = true
				}
			}
			if !found {
				return errResult("subject commonName is not one of the subjectAltName ipAddress values")
			}
		} else if !slices.Contains(c.DNSNames, cn) {
			return errResult("subject commonName is not one of the subjectAltName dNSName values")
		}
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1079
	// |     `subjectPublicKeyInfo`               | See Sections [6.1.5](#615-key-sizes), [6.1.6](#616-public-key-parameters-generation-and-quality-checking), and [7.1.3.1](#7131-subjectpublickeyinfo) |
	// Section 6.1.5 says public keys in Subscriber Certificates are "either
	// RSA keys whose encoded modulus size is 2048, 3072, or 4096 bits; or
	// ECDSA keys which are a valid point on the NIST P-256, P-384, or P-521
	// elliptic curves". Section 6.1.6 requires the key parameter quality
	// checks performed inline below. Section 7.1.3.1 requires the
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
		if encodedModulusBits != 2048 && encodedModulusBits != 3072 && encodedModulusBits != 4096 {
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
		var wantAlgID string
		var ecdhCurve ecdh.Curve
		switch key.Pub.Curve {
		case elliptic.P256():
			wantAlgID = spkiAlgorithmP256
			ecdhCurve = ecdh.P256()
		case elliptic.P384():
			wantAlgID = spkiAlgorithmP384
			ecdhCurve = ecdh.P384()
		case elliptic.P521():
			wantAlgID = spkiAlgorithmP521
			ecdhCurve = ecdh.P521()
		default:
			return errResult(fmt.Sprintf("ECDSA curve %s is not allowed", key.Pub.Curve.Params().Name))
		}
		if hex.EncodeToString(spkiAlgID) != wantAlgID {
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
		_, err = ecdhCurve.NewPublicKey(key.Raw.Bytes)
		if err != nil {
			return errResult("ECDSA public key is not a valid uncompressed point on its curve")
		}
	default:
		return errResult(fmt.Sprintf("unsupported public key type %T", c.PublicKey))
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1080
	// |     `issuerUniqueID`                     | Not present |
	if c.IssuerUniqueId.Bytes != nil {
		return errResult("issuerUniqueID is present")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1081
	// |     `subjectUniqueID`                    | Not present |
	if c.SubjectUniqueId.Bytes != nil {
		return errResult("subjectUniqueID is present")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1083
	// |         `authorityInformationAccess`     | Contains the HTTP URI of the Issuing CA's Certificate |
	// Whether the URI actually serves the Issuing CA's certificate is not
	// observable here, but the extension must contain exactly one caIssuers
	// entry with an http URI and nothing else (in particular, no OCSP
	// entries).
	aiaExt := getExtension(c, authorityInformationAccessOID)
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

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1084
	// |         `authorityKeyIdentifier`         | Contains a `keyIdentifier` byte-for-byte identical to the `subjectKeyIdentifier` of the Issuing CA |
	akidExt := getExtension(c, authorityKeyIdentifierOID)
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

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1085
	// |         `basicConstraints`               | Critical, with `cA` set to false |
	bcExt := getExtension(c, basicConstraintsOID)
	if bcExt == nil {
		return errResult("basicConstraints extension is not present")
	}
	if !bcExt.Critical {
		return errResult("basicConstraints extension is not critical")
	}
	if c.IsCA {
		return errResult("basicConstraints cA is not false")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1086
	// |         `certificatePolicies`            | Contains only the Baseline Requirements Domain Validated Reserved Policy Identifier (OID 2.23.140.1.2.1) |
	cpExt := getExtension(c, certificatePoliciesOID)
	if cpExt == nil {
		return errResult("certificatePolicies extension is not present")
	}
	if cpExt.Critical {
		return errResult("certificatePolicies extension is critical")
	}
	if len(c.PolicyIdentifiers) != 1 || !c.PolicyIdentifiers[0].Equal(domainValidatedOID) {
		return errResult("certificatePolicies does not contain exactly the Domain Validated Reserved Policy Identifier")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1087
	// |         `crlDistributionPoints`          | Contains the HTTP URI of a CRL issued by the Issuing CA whose scope includes this certificate |
	// Whether the CRL's scope actually includes this certificate is not
	// observable here.
	crldpExt := getExtension(c, crlDistributionPointsOID)
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

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1088
	// |         `extKeyUsage`                    | Contains only `id-kp-serverAuth` (OID 1.3.6.1.5.5.7.3.1) |
	ekuExt := getExtension(c, extKeyUsageOID)
	if ekuExt == nil {
		return errResult("extKeyUsage extension is not present")
	}
	if ekuExt.Critical {
		return errResult("extKeyUsage extension is critical")
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(c.UnknownExtKeyUsage) != 0 {
		return errResult("extKeyUsage does not contain exactly id-kp-serverAuth")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1089
	// |         `keyUsage`                       | Critical, with only the `digitalSignature` (0) bit (and optionally the `keyEncipherment` (2) bit, for RSA keys) set |
	kuExt := getExtension(c, keyUsageOID)
	if kuExt == nil {
		return errResult("keyUsage extension is not present")
	}
	if !kuExt.Critical {
		return errResult("keyUsage extension is not critical")
	}
	if c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errResult("keyUsage does not assert digitalSignature")
	}
	allowedKeyUsage := x509.KeyUsageDigitalSignature
	_, isRSA := c.PublicKey.(*zrsa.PublicKey)
	if isRSA {
		allowedKeyUsage |= x509.KeyUsageKeyEncipherment
	}
	if c.KeyUsage&^allowedKeyUsage != 0 {
		return errResult("keyUsage asserts bits beyond digitalSignature (and keyEncipherment, for RSA keys)")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1091
	// |         `subjectAltName`                 | A sequence of 1 to 100 names of type `dNSName` or `ipAddress` (critical if CN omitted) |
	sanExt := getExtension(c, subjectAltNameOID)
	if sanExt == nil {
		return errResult("subjectAltName extension is not present")
	}
	if len(c.OtherNames) != 0 || len(c.EmailAddresses) != 0 || len(c.DirectoryNames) != 0 ||
		len(c.EDIPartyNames) != 0 || len(c.URIs) != 0 || len(c.RegisteredIDs) != 0 {
		return errResult("subjectAltName contains a name of a type other than dNSName or ipAddress")
	}
	totalNames := len(c.DNSNames) + len(c.IPAddresses)
	if totalNames < 1 || totalNames > 100 {
		return errResult("subjectAltName does not contain between 1 and 100 names")
	}
	if c.Subject.CommonName == "" && !sanExt.Critical {
		return errResult("subjectAltName extension is not critical despite the subject commonName being omitted")
	}
	if c.Subject.CommonName != "" && sanExt.Critical {
		return errResult("subjectAltName extension is critical despite the subject commonName being present")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1092
	// |         `subjectKeyIdentifier`           | Optionally contains a truncated hash of the `subjectPublicKey`, per Section 2(1) of RFC 7093 |
	skidExt := getExtension(c, subjectKeyIdentifierOID)
	if skidExt != nil {
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
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1094
	// | `signatureAlgorithm`                     | Byte-for-byte identical to the `tbsCertificate.signature` |
	signatureAlgorithm, err := getOuterSignatureAlgorithm(c.Raw)
	if err != nil {
		return errResult(err.Error())
	}
	if !bytes.Equal(tbsSignature, signatureAlgorithm) {
		return errResult("signatureAlgorithm is not byte-for-byte identical to the tbsCertificate.signature")
	}

	// https://github.com/letsencrypt/cp-cps/blob/TKTK-replace-with-version-tag/CP-CPS.md?plain=1#L1095
	// | `signatureValue`                         | A signature appropriate to the `signatureAlgorithm` field |
	// We can't verify the signature here: pre-issuance linting operates on a
	// certificate signed by a throwaway key.

	return nil
}
