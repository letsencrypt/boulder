package cpcps

import (
	"bytes"
	"crypto/elliptic"
	stdx509 "crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/zmap/zcrypto/encoding/asn1"
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
// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L992-L1012
func (l *rootCACertificateMatchesCPSProfile) Execute(c *x509.Certificate) *lint.LintResult {
	// version is "X.509 version 3" (Section 7.1.1). Note that unlike
	// crypto/x509, zcrypto's Version field is one-indexed: it holds 3 (not the
	// raw encoded value 2) for a v3 certificate.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L997
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1101-L1103
	if c.Version != 3 {
		return errResult("version is not v3")
	}

	// serialNumber is "Approximately 128 bits, including at least 64 bits of
	// output from a CSPRNG". We can't test randomness here, but a 128-bit
	// serial occupies exactly 16 bytes.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L998
	if c.SerialNumber == nil || c.SerialNumber.Sign() <= 0 {
		return errResult("serialNumber is not a positive integer")
	}
	if (c.SerialNumber.BitLen()+7)/8 != 16 {
		return errResult("serialNumber is not approximately 128 bits")
	}

	// signature is byte-for-byte identical to one of the hexadecimal encodings
	// specified by Section 7.1.3.2 of the Baseline Requirements (Section
	// 7.1.3.2).
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L999
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1115-L1117
	tbsSignature, err := util.GetSignatureAlgorithmInTBSEncoded(c)
	if err != nil {
		return errResult("failed to parse tbsCertificate.signature")
	}
	if !brSignatureAlgorithmIdentifiers[hex.EncodeToString(tbsSignature)] {
		return errResult("signature is not byte-for-byte identical to a BRs Section 7.1.3.2 encoding")
	}

	// issuer is "Byte-for-byte identical to the subject field".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1000
	if !bytes.Equal(c.RawIssuer, c.RawSubject) {
		return errResult("issuer is not byte-for-byte identical to the subject")
	}

	// validity is "At most 3660 days (approx. 10 years)". RFC 5280 4.1.2.5:
	// "The validity period for a certificate is the period of time from
	// notBefore through notAfter, inclusive."
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1001
	if c.NotAfter.Before(c.NotBefore) {
		return errResult("validity is negative: notAfter is before notBefore")
	}
	if c.NotAfter.Add(time.Second).Sub(c.NotBefore) > 3660*lints.BRDay {
		return errResult("validity is more than 3660 days")
	}

	// subject is "C=US, O=ISRG, and a unique CN".
	// We can't test for CN uniqueness here, but the rest we can check.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1002
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

	// subjectPublicKeyInfo: Section 6.1.5 says Root CA key pairs are "either
	// RSA keys whose encoded modulus size is 4096 bits, or ECDSA keys which
	// are a valid point on the NIST P-384 elliptic curve", and Section 7.1.3.1
	// requires the AlgorithmIdentifier to be byte-for-byte identical to a BRs
	// Section 7.1.3.1 encoding. Point-on-curve validation is performed by
	// zcrypto at parse time.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1003
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
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1004
	if c.IssuerUniqueId.Bytes != nil {
		return errResult("issuerUniqueID is present")
	}

	// subjectUniqueID is "Not present".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1005
	if c.SubjectUniqueId.Bytes != nil {
		return errResult("subjectUniqueID is present")
	}

	// basicConstraints is "Critical, with cA set to true".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1007
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

	// keyUsage is "Critical, with only the keyCertSign (5) and cRLSign (6)
	// bits set".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1008
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

	// subjectKeyIdentifier "Contains a truncated hash of the subjectPublicKey,
	// per Section 2(1) of RFC 7093".
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1009
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
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1010
	allowedExtensions := []asn1.ObjectIdentifier{
		basicConstraintsOID,
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
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1011
	signatureAlgorithm, err := getOuterSignatureAlgorithm(c.Raw)
	if err != nil {
		return errResult(err.Error())
	}
	if !bytes.Equal(tbsSignature, signatureAlgorithm) {
		return errResult("signatureAlgorithm is not byte-for-byte identical to the tbsCertificate.signature")
	}

	// signatureValue is "A signature appropriate to the signatureAlgorithm
	// field". We can't verify the signature under pre-issuance linting (the
	// certificate is signed by a throwaway key), but CheckApplies only selects
	// certificates whose self-signature zcrypto has verified.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1012

	return &lint.LintResult{Status: lint.Pass}
}
