package cpcps

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/zmap/zcrypto/encoding/asn1"
	zrsa "github.com/zmap/zcrypto/rsa"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"github.com/letsencrypt/boulder/linter/lints"
)

type crossCertifiedSubordinateCACertificateMatchesCPSProfile struct {
	// Config is filled from the shared [Global] stanza of the lint
	// configuration; see IssuingCAConfig.
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
	return util.IsSubCA(c) && isCrossCertified(c)
}

// Execute checks the given certificate against the Cross-Certified Subordinate
// CA Certificate Profile, row by row.
// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1014-L1039
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

	// version is "X.509 version 3" (Section 7.1.1). Note that unlike
	// crypto/x509, zcrypto's Version field is one-indexed: it holds 3 (not the
	// raw encoded value 2) for a v3 certificate.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1019
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1101-L1103
	if c.Version != 3 {
		return errResult("version is not v3")
	}

	// serialNumber is "Approximately 128 bits, including at least 64 bits of
	// output from a CSPRNG". We can't test randomness here, but a 128-bit
	// serial occupies exactly 16 bytes.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1020
	if c.SerialNumber == nil || c.SerialNumber.Sign() <= 0 {
		return errResult("serialNumber is not a positive integer")
	}
	if (c.SerialNumber.BitLen()+7)/8 != 16 {
		return errResult("serialNumber is not approximately 128 bits")
	}

	// signature is byte-for-byte identical to one of the hexadecimal encodings
	// specified by Section 7.1.3.2 of the Baseline Requirements (Section
	// 7.1.3.2).
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1021
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
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1022
	if !bytes.Equal(c.RawIssuer, issuer.RawSubject) {
		return errResult("issuer is not byte-for-byte identical to the subject of the configured Issuing CA")
	}

	// validity is "At most 1098 days (approx. 3 years)". RFC 5280 4.1.2.5:
	// "The validity period for a certificate is the period of time from
	// notBefore through notAfter, inclusive."
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1023
	if c.NotAfter.Add(time.Second).Sub(c.NotBefore) > 1098*lints.BRDay {
		return errResult("validity is more than 1098 days")
	}

	// subject is "Byte-for-byte identical to the subject field of the existing
	// CA Certificate". The shape checks below are implied by the byte-for-byte
	// comparison, but produce more useful error messages.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1024
	if !bytes.Equal(c.RawSubject, existing.RawSubject) {
		return errResult("subject is not byte-for-byte identical to the subject of the configured existing CA Certificate")
	}
	if len(c.Subject.Names) != 3 {
		return errResult("subject does not contain exactly C, O, and CN attributes")
	}
	if len(c.Subject.Country) != 1 || c.Subject.Country[0] != "US" {
		return errResult("subject countryName is not US")
	}
	if c.Subject.CommonName == "" {
		return errResult("subject commonName is empty")
	}

	// subjectPublicKeyInfo: the subject of a cross-certificate is an existing
	// ISRG root, so Section 6.1.5's Root CA requirements apply to its key:
	// "either RSA keys whose encoded modulus size is 4096 bits, or ECDSA keys
	// which are a valid point on the NIST P-384 elliptic curve". Section
	// 7.1.3.1 requires the AlgorithmIdentifier to be byte-for-byte identical
	// to a BRs Section 7.1.3.1 encoding. Point-on-curve validation is
	// performed by zcrypto at parse time.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1025
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L852
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1111-L1113
	spkiAlgID, err := util.GetPublicKeyAidEncoded(c)
	if err != nil {
		return errResult("failed to parse subjectPublicKeyInfo algorithm")
	}
	switch key := c.PublicKey.(type) {
	case *zrsa.PublicKey:
		if key.N.BitLen() != 4096 {
			return errResult(fmt.Sprintf("RSA modulus size %d is not allowed", key.N.BitLen()))
		}
		if hex.EncodeToString(spkiAlgID) != spkiAlgorithmRSA {
			return errResult("public key algorithm is not byte-for-byte identical to the BRs Section 7.1.3.1 RSA encoding")
		}
	case *x509.AugmentedECDSA:
		if key.Pub.Curve != elliptic.P384() {
			return errResult(fmt.Sprintf("ECDSA curve %s is not allowed", key.Pub.Curve.Params().Name))
		}
		if hex.EncodeToString(spkiAlgID) != spkiAlgorithmP384 {
			return errResult("public key algorithm is not byte-for-byte identical to the BRs Section 7.1.3.1 encoding for its curve")
		}
	default:
		return errResult(fmt.Sprintf("unsupported public key type %T", c.PublicKey))
	}

	// issuerUniqueID is "Not present".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1026
	if c.IssuerUniqueId.BitLength != 0 || len(c.IssuerUniqueId.Bytes) != 0 {
		return errResult("issuerUniqueID is present")
	}

	// subjectUniqueID is "Not present".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1027
	if c.SubjectUniqueId.BitLength != 0 || len(c.SubjectUniqueId.Bytes) != 0 {
		return errResult("subjectUniqueID is present")
	}

	// authorityInformationAccess "Contains the HTTP URI of the Issuing CA's
	// Certificate". Whether the URI actually serves the Issuing CA's
	// certificate is not observable here, but the extension must contain
	// exactly one caIssuers entry with an http URI and nothing else (in
	// particular, no OCSP entries).
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1029
	if !util.IsExtInCert(c, authorityInformationAccessOID) {
		return errResult("authorityInformationAccess extension is not present")
	}
	if len(c.OCSPServer) != 0 {
		return errResult("authorityInformationAccess contains an OCSP entry")
	}
	if len(c.IssuingCertificateURL) != 1 {
		return errResult("authorityInformationAccess does not contain exactly one caIssuers entry")
	}
	if !strings.HasPrefix(c.IssuingCertificateURL[0], "http://") {
		return errResult("authorityInformationAccess caIssuers URI does not use the http scheme")
	}

	// authorityKeyIdentifier "Contains a keyIdentifier byte-for-byte identical
	// to the subjectKeyIdentifier of the Issuing CA".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1030
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
	// identical to the existing CA Certificate".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1031
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
	if c.MaxPathLen != existing.MaxPathLen || c.MaxPathLenZero != existing.MaxPathLenZero {
		return errResult("basicConstraints pathLenConstraint is not identical to that of the configured existing CA Certificate")
	}

	// certificatePolicies "Contains only the Baseline Requirements Domain
	// Validated Reserved Policy Identifier (OID 2.23.140.1.2.1)".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1032
	if !util.IsExtInCert(c, certificatePoliciesOID) {
		return errResult("certificatePolicies extension is not present")
	}
	if len(c.PolicyIdentifiers) != 1 || !c.PolicyIdentifiers[0].Equal(domainValidatedOID) {
		return errResult("certificatePolicies does not contain exactly the Domain Validated Reserved Policy Identifier")
	}

	// crlDistributionPoints "Contains the HTTP URI of a CRL issued by the
	// Issuing CA whose scope includes this certificate". Whether the CRL's
	// scope actually includes this certificate is not observable here.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1033
	if !util.IsExtInCert(c, crlDistributionPointsOID) {
		return errResult("crlDistributionPoints extension is not present")
	}
	if len(c.CRLDistributionPoints) != 1 {
		return errResult("crlDistributionPoints does not contain exactly one distribution point")
	}
	if !strings.HasPrefix(c.CRLDistributionPoints[0], "http://") {
		return errResult("crlDistributionPoints URI does not use the http scheme")
	}

	// extKeyUsage "Contains only id-kp-serverAuth (OID 1.3.6.1.5.5.7.3.1)".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1034
	if !util.IsExtInCert(c, extKeyUsageOID) {
		return errResult("extKeyUsage extension is not present")
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(c.UnknownExtKeyUsage) != 0 {
		return errResult("extKeyUsage does not contain exactly id-kp-serverAuth")
	}

	// keyUsage is "Critical, with only the keyCertSign (5) and cRLSign (6)
	// bits set".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1035
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

	// subjectKeyIdentifier is "Byte-for-byte identical to the
	// subjectKeyIdentifier of the existing CA Certificate". Unlike the other
	// profiles we cannot assume the RFC 7093 construction here, because the
	// existing CA Certificate's subjectKeyIdentifier may have been computed by
	// any method.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1036
	skidExt := getExtension(c, subjectKeyIdentifierOID)
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

	// Any other extension is "Not present".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1037
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
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1038
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
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1039

	return &lint.LintResult{Status: lint.Pass}
}
