package cpcps

import (
	"bytes"
	"crypto/ecdh"
	"crypto/elliptic"
	stdx509 "crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/weppos/publicsuffix-go/publicsuffix"
	"github.com/zmap/zcrypto/encoding/asn1"
	zrsa "github.com/zmap/zcrypto/rsa"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/linter/lints"
)

type tlsSubordinateCACertificateMatchesCPSProfile struct {
	// Config is filled from the shared [Global] stanza of the lint
	// configuration; see IssuingCAConfig.
	Config *SharedConfig
}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_tls_subordinate_ca_certificate_matches_cps_profile",
			Description:   "Let's Encrypt TLS Subordinate CA Certificates are issued in accordance with the CP/CPS Profile",
			Citation:      "CPS: 7.1",
			Source:        lints.LetsEncryptCPS,
			EffectiveDate: lints.CPSV62Date,
		},
		Lint: NewTLSSubordinateCACertificateMatchesCPSProfile,
	})
}

func NewTLSSubordinateCACertificateMatchesCPSProfile() lint.CertificateLintInterface {
	return &tlsSubordinateCACertificateMatchesCPSProfile{}
}

// Configure implements the lint.Configurable interface.
func (l *tlsSubordinateCACertificateMatchesCPSProfile) Configure() any {
	return l
}

// isCrossCertified is a heuristic for distinguishing the two kinds of
// subordinate CA certificates that ISRG issues. A Cross-Certified Subordinate
// CA Certificate confers a second issuance path upon an existing CA, so its
// subject is byte-for-byte identical to that existing CA Certificate's
// subject; in practice the existing CA is always an ISRG root (subject
// O=ISRG), while TLS Subordinate CA Certificates are required to have subject
// O=Let's Encrypt.
func isCrossCertified(c *x509.Certificate) bool {
	return len(c.Subject.Organization) == 1 && c.Subject.Organization[0] == "ISRG"
}

func (l *tlsSubordinateCACertificateMatchesCPSProfile) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubCA(c) && !isCrossCertified(c)
}

// Execute checks the given certificate against the TLS Subordinate CA
// Certificate Profile, row by row.
// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1041-L1066
func (l *tlsSubordinateCACertificateMatchesCPSProfile) Execute(c *x509.Certificate) *lint.LintResult {
	// Several rows of the profile require byte-for-byte correspondence with
	// the Issuing CA's certificate, so this lint must be configured with it.
	issuer, err := parseConfiguredCertificate(l.Config.issuerPEM())
	if err != nil {
		return fatalResult(err.Error())
	}
	if issuer == nil {
		return fatalResult("lint has not been configured with the Issuing CA's certificate (issuer_certificate)")
	}

	// version is "X.509 version 3" (Section 7.1.1). Note that unlike
	// crypto/x509, zcrypto's Version field is one-indexed: it holds 3 (not the
	// raw encoded value 2) for a v3 certificate.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1046
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1101-L1103
	if c.Version != 3 {
		return errResult("version is not v3")
	}

	// serialNumber is "More than 100 bits of output from a CSPRNG, optionally
	// with additional non-random bits". We can't test randomness here, but a
	// serial containing more than 100 bits of CSPRNG output must itself be
	// more than 100 bits long.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1047
	if c.SerialNumber == nil || c.SerialNumber.Sign() <= 0 {
		return errResult("serialNumber is not a positive integer")
	}
	if c.SerialNumber.BitLen() <= 100 {
		return errResult("serialNumber is not more than 100 bits long")
	}

	// signature is byte-for-byte identical to one of the hexadecimal encodings
	// specified by Section 7.1.3.2 of the Baseline Requirements (Section
	// 7.1.3.2).
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1048
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1115-L1117
	tbsSignature, err := util.GetSignatureAlgorithmInTBSEncoded(c)
	if err != nil {
		return errResult("failed to parse tbsCertificate.signature")
	}
	if !brSignatureAlgorithmIdentifiers[hex.EncodeToString(tbsSignature)] {
		return errResult("signature is not byte-for-byte identical to a BRs Section 7.1.3.2 encoding")
	}

	// issuer is "Byte-for-byte identical to the subject field of the Issuing
	// CA".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1049
	if !bytes.Equal(c.RawIssuer, issuer.RawSubject) {
		return errResult("issuer is not byte-for-byte identical to the subject of the configured Issuing CA")
	}

	// validity is "At most 1098 days (approx. 3 years)". RFC 5280 4.1.2.5:
	// "The validity period for a certificate is the period of time from
	// notBefore through notAfter, inclusive."
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1050
	if c.NotAfter.Before(c.NotBefore) {
		return errResult("validity is negative: notAfter is before notBefore")
	}
	if c.NotAfter.Add(time.Second).Sub(c.NotBefore) > 1098*lints.BRDay {
		return errResult("validity is more than 1098 days")
	}

	// subject is "C=US, O=Let's Encrypt, and a unique CN".
	// We can't test for CN uniqueness here, but the rest we can check.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1051
	if len(c.Subject.Names) != 3 {
		return errResult("subject does not contain exactly C, O, and CN attributes")
	}
	if len(c.Subject.Country) != 1 || c.Subject.Country[0] != "US" {
		return errResult("subject countryName is not US")
	}
	if len(c.Subject.Organization) != 1 || c.Subject.Organization[0] != "Let's Encrypt" {
		return errResult("subject organizationName is not Let's Encrypt")
	}
	if c.Subject.CommonName == "" {
		return errResult("subject commonName is empty")
	}

	// subjectPublicKeyInfo: Section 6.1.5 says Subordinate CA key pairs are
	// "either RSA keys whose encoded modulus size is 2048 bits, or ECDSA keys
	// which are a valid point on the NIST P-384 elliptic curve", Section 6.1.6
	// requires the key parameter quality checks performed inline below, and
	// Section 7.1.3.1 requires the AlgorithmIdentifier to be byte-for-byte
	// identical to a BRs Section 7.1.3.1 encoding. Point-on-curve validation
	// is also performed by zcrypto at parse time.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1052
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L854
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L858-L862
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1111-L1113
	spkiAlgID, err := util.GetPublicKeyAidEncoded(c)
	if err != nil {
		return errResult("failed to parse subjectPublicKeyInfo algorithm")
	}
	switch key := c.PublicKey.(type) {
	case *zrsa.PublicKey:
		if key.N.BitLen() != 2048 {
			return errResult(fmt.Sprintf("RSA modulus size %d is not allowed", key.N.BitLen()))
		}
		if hex.EncodeToString(spkiAlgID) != spkiAlgorithmRSA {
			return errResult("public key algorithm is not byte-for-byte identical to the BRs Section 7.1.3.1 RSA encoding")
		}
		// Section 6.1.6, via NIST SP 800-89 Section 5.3.3, requires that RSA
		// keys have "a public exponent of 65537 and an odd modulus which has
		// no factors smaller than 752".
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
		_, err = ecdh.P384().NewPublicKey(key.Raw.Bytes)
		if err != nil {
			return errResult("ECDSA public key is not a valid uncompressed point on its curve")
		}
	default:
		return errResult(fmt.Sprintf("unsupported public key type %T", c.PublicKey))
	}

	// issuerUniqueID is "Not present".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1053
	if c.IssuerUniqueId.Bytes != nil {
		return errResult("issuerUniqueID is present")
	}

	// subjectUniqueID is "Not present".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1054
	if c.SubjectUniqueId.Bytes != nil {
		return errResult("subjectUniqueID is present")
	}

	// authorityInformationAccess "Contains the HTTP URI of the Issuing CA's
	// Certificate". Whether the URI actually serves the Issuing CA's
	// certificate is not observable here, but the extension must contain
	// exactly one caIssuers entry with an http URI and nothing else (in
	// particular, no OCSP entries).
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1056
	if !util.IsExtInCert(c, authorityInformationAccessOID) {
		return errResult("authorityInformationAccess extension is not present")
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

	// authorityKeyIdentifier "Contains a keyIdentifier byte-for-byte identical
	// to the subjectKeyIdentifier of the Issuing CA".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1057
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

	// basicConstraints is "Critical, with cA set to true and pathLenConstraint
	// set to 0".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1058
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
	if c.MaxPathLen != 0 || !c.MaxPathLenZero {
		return errResult("basicConstraints pathLenConstraint is not 0")
	}

	// certificatePolicies "Contains only the Baseline Requirements Domain
	// Validated Reserved Policy Identifier (OID 2.23.140.1.2.1)".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1059
	if !util.IsExtInCert(c, certificatePoliciesOID) {
		return errResult("certificatePolicies extension is not present")
	}
	if len(c.PolicyIdentifiers) != 1 || !c.PolicyIdentifiers[0].Equal(domainValidatedOID) {
		return errResult("certificatePolicies does not contain exactly the Domain Validated Reserved Policy Identifier")
	}

	// crlDistributionPoints "Contains the HTTP URI of a CRL issued by the
	// Issuing CA whose scope includes this certificate". Whether the CRL's
	// scope actually includes this certificate is not observable here.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1060
	if !util.IsExtInCert(c, crlDistributionPointsOID) {
		return errResult("crlDistributionPoints extension is not present")
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

	// extKeyUsage "Contains only id-kp-serverAuth (OID 1.3.6.1.5.5.7.3.1)".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1061
	if !util.IsExtInCert(c, extKeyUsageOID) {
		return errResult("extKeyUsage extension is not present")
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(c.UnknownExtKeyUsage) != 0 {
		return errResult("extKeyUsage does not contain exactly id-kp-serverAuth")
	}

	// keyUsage is "Critical, with only the digitalSignature (0), keyCertSign
	// (5), and cRLSign (6) bits set".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1062
	kuExt := getExtension(c, keyUsageOID)
	if kuExt == nil {
		return errResult("keyUsage extension is not present")
	}
	if !kuExt.Critical {
		return errResult("keyUsage extension is not critical")
	}
	if c.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		return errResult("keyUsage does not assert exactly the bits required by the profile")
	}

	// subjectKeyIdentifier "Contains a truncated hash of the subjectPublicKey,
	// per Section 2(1) of RFC 7093".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1063
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

	// Any other extension is "Not present".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1064
	allowedExtensions := []asn1.ObjectIdentifier{
		authorityInformationAccessOID,
		authorityKeyIdentifierOID,
		basicConstraintsOID,
		certificatePoliciesOID,
		crlDistributionPointsOID,
		extKeyUsageOID,
		keyUsageOID,
		subjectKeyIdentifierOID,
	}
	for _, ext := range c.Extensions {
		found := false
		for _, oid := range allowedExtensions {
			if ext.Id.Equal(oid) {
				found = true
			}
		}
		if !found {
			return errResult(fmt.Sprintf("unexpected extension %s", ext.Id.String()))
		}
	}

	// signatureAlgorithm is "Byte-for-byte identical to the
	// tbsCertificate.signature".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1065
	signatureAlgorithm, err := getOuterSignatureAlgorithm(c.Raw)
	if err != nil {
		return errResult(err.Error())
	}
	if !bytes.Equal(tbsSignature, signatureAlgorithm) {
		return errResult("signatureAlgorithm is not byte-for-byte identical to the tbsCertificate.signature")
	}

	// signatureValue is "A signature appropriate to the signatureAlgorithm
	// field". We can't verify the signature here: pre-issuance linting
	// operates on a certificate signed by a throwaway key.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1066

	return &lint.LintResult{Status: lint.Pass}
}
