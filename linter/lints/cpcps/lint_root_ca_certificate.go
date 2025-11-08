package cpcps

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

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
			EffectiveDate: lints.GenYHierarchyDate,
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

func (l *rootCACertificateMatchesCPSProfile) Execute(c *x509.Certificate) *lint.LintResult {
	certificate := cryptobyte.String(c.Raw)

	var tbsCertificate cryptobyte.String
	if !certificate.ReadASN1(&tbsCertificate, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse tbsCertificate"}
	}

	// version is "X.509 version 3".
	var version int64
	if !tbsCertificate.ReadASN1Int64WithTag(&version, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse version"}
	}

	if version != 2 {
		return &lint.LintResult{Status: lint.Error, Details: "version is not v3(2)"}
	}

	// serialNumber is "Approximately 128 bits, including at least 64 bits of
	// output from a CSPRNG."
	// We can't test randomness here, but length we can check.
	var serialNumber []byte
	if !tbsCertificate.ReadASN1Bytes(&serialNumber, cryptobyte_asn1.INTEGER) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse serialNumber"}
	}

	if len(serialNumber) < 16 || len(serialNumber) > 17 {
		return &lint.LintResult{Status: lint.Error, Details: "serialNumber is not approximately 128 bits"}
	}

	// signature AlgorithmIdentifier is "byte-for-byte identical with one of the
	// hexadecimal encodings specified by Section 7.1.3.2 of the BRs".
	var signature cryptobyte.String
	if !tbsCertificate.ReadASN1(&signature, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse signature"}
	}

	signatureAlgorithmIdentifierHex := hex.EncodeToString(signature)
	if signatureAlgorithmIdentifierHex != "300a06082a8648ce3d040303" &&
		signatureAlgorithmIdentifierHex != "300d06092a864886f70d01010b0500" {
		return &lint.LintResult{Status: lint.Error, Details: "signature is not byte-for-byte identical with BRs-approved hex string"}
	}

	// issuer is "Byte-for-byte identical to the subject".
	// The actual comparison happens below, after parsing the subject.
	var issuer cryptobyte.String
	if !tbsCertificate.ReadASN1(&issuer, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse issuer"}
	}

	// validity is "At most 9132 days"
	var validity cryptobyte.String
	if !tbsCertificate.ReadASN1(&validity, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse validity"}
	}

	var notBefore time.Time
	if !validity.ReadASN1UTCTime(&notBefore) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse notBefore"}
	}

	var notAfter time.Time
	if !validity.ReadASN1UTCTime(&notAfter) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse notAfter"}
	}

	if notAfter.Add(time.Second).Sub(notBefore) > 9132*24*time.Hour {
		return &lint.LintResult{Status: lint.Error, Details: "validity is more that 9132 days"}
	}

	// subject is "C=US, O=ISRG, and a unique CN".
	// We can't test for CN uniqueness here, but the rest we can check.
	var subject cryptobyte.String
	if !tbsCertificate.ReadASN1(&subject, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse subject"}
	}

	if !bytes.Equal(issuer, subject) {
		return &lint.LintResult{Status: lint.Error, Details: "issuer is not byte-for-byte identical to subject"}
	}

	var subjectRNDSequence cryptobyte.String
	if !subject.ReadASN1(&subjectRNDSequence, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse rdnSequence"}
	}

	var countryNameRDN cryptobyte.String
	if !subjectRNDSequence.ReadASN1(&countryNameRDN, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse countryName RDN"}
	}

	var countryNameATV cryptobyte.String
	if !countryNameRDN.ReadASN1(&countryNameATV, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse countryName ATV"}
	}

	var countryNameOID asn1.ObjectIdentifier
	if !countryNameATV.ReadASN1ObjectIdentifier(&countryNameOID) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse countryName OID"}
	}

	if !countryNameOID.Equal(asn1.ObjectIdentifier{2, 5, 4, 6}) {
		return &lint.LintResult{Status: lint.Error, Details: "subject doesn't have countryName OID first"}
	}

	var countryNameValue []byte
	if !countryNameATV.ReadASN1Bytes(&countryNameValue, cryptobyte_asn1.PrintableString) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse countryName value"}
	}

	if string(countryNameValue) != "US" {
		return &lint.LintResult{Status: lint.Error, Details: "countryName is not US"}
	}

	var organizationNameRDN cryptobyte.String
	if !subjectRNDSequence.ReadASN1(&organizationNameRDN, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse organizationName RDN"}
	}

	var organizationNameATV cryptobyte.String
	if !organizationNameRDN.ReadASN1(&organizationNameATV, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse organizationName ATV"}
	}

	var organizationNameOID asn1.ObjectIdentifier
	if !organizationNameATV.ReadASN1ObjectIdentifier(&organizationNameOID) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse organizationName OID"}
	}

	if !organizationNameOID.Equal(asn1.ObjectIdentifier{2, 5, 4, 6}) {
		return &lint.LintResult{Status: lint.Error, Details: "subject doesn't have organizationName OID second"}
	}

	var organizationNameValue []byte
	if !organizationNameATV.ReadASN1Bytes(&organizationNameValue, cryptobyte_asn1.PrintableString) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse organizationName value"}
	}

	if string(organizationNameValue) != "ISRG" {
		return &lint.LintResult{Status: lint.Error, Details: "organizationName is not ISRG"}
	}

	var commonNameRDN cryptobyte.String
	if !subjectRNDSequence.ReadASN1(&commonNameRDN, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse commonName RDN"}
	}

	var commonNameATV cryptobyte.String
	if !commonNameRDN.ReadASN1(&commonNameATV, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse commonName ATV"}
	}

	var commonNameOID asn1.ObjectIdentifier
	if !commonNameATV.ReadASN1ObjectIdentifier(&commonNameOID) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse commonName OID"}
	}

	if !commonNameOID.Equal(asn1.ObjectIdentifier{2, 5, 4, 6}) {
		return &lint.LintResult{Status: lint.Error, Details: "subject doesn't have commonName OID third"}
	}

	var commonNameValue []byte
	if !commonNameATV.ReadASN1Bytes(&commonNameValue, cryptobyte_asn1.PrintableString) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse commonName value"}
	}

	if len(commonNameValue) == 0 {
		return &lint.LintResult{Status: lint.Error, Details: "commonName is empty"}
	}

	// subjectPublicKeyInfo is "either RSA keys whose encoded modulus size is 4096
	// bits, or ECDSA keys which are a valid point on the NIST P-384 elliptic
	// curve", and "byte-for-byte identical with one of the hexadecimal encodings
	// specified by Section 7.1.3.1 of the Baseline Requirements".
	var subjectPublicKeyInfo cryptobyte.String
	if !tbsCertificate.ReadASN1(&subjectPublicKeyInfo, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse subjectPublicKeyInfo"}
	}

	var algorithm cryptobyte.String
	if !subjectPublicKeyInfo.ReadASN1(&algorithm, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse subject public key algorithm"}
	}

	spkiAlgorithmIdentifierHex := hex.EncodeToString(algorithm)
	if spkiAlgorithmIdentifierHex != "301006072a8648ce3d020106052b81040022" &&
		spkiAlgorithmIdentifierHex != "300d06092a864886f70d0101010500" {
		return &lint.LintResult{Status: lint.Error, Details: "public key algorithm is not byte-for-byte identical with BRs-approved hex string"}
	}

	var subjectPublicKey asn1.BitString
	if !subjectPublicKeyInfo.ReadASN1BitString(&subjectPublicKey) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse subjectPublicKey"}
	}

	// issuerUniqueID is "Not present".
	if tbsCertificate.PeekASN1Tag(cryptobyte_asn1.Tag(1).ContextSpecific()) {
		return &lint.LintResult{Status: lint.Error, Details: "certificate contains issuerUniqueID"}
	}

	// subjectUniqueID is "Not present".
	if tbsCertificate.PeekASN1Tag(cryptobyte_asn1.Tag(2).ContextSpecific()) {
		return &lint.LintResult{Status: lint.Error, Details: "certificate contains subjectUniqueID"}
	}

	// extensions has three entries detailed below.
	var extensions cryptobyte.String
	if !tbsCertificate.ReadASN1(&extensions, cryptobyte_asn1.Tag(3).Constructed().ContextSpecific()) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse extensions"}
	}

	var extensionsSequence cryptobyte.String
	if !extensions.ReadASN1(&extensionsSequence, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse extensions sequence"}
	}

	for range 3 {
		var ext cryptobyte.String
		if !extensionsSequence.ReadASN1(&ext, cryptobyte_asn1.SEQUENCE) {
			return &lint.LintResult{Status: lint.Error, Details: "failed to parse extension"}
		}

		var extnID asn1.ObjectIdentifier
		if !ext.ReadASN1ObjectIdentifier(&extnID) {
			return &lint.LintResult{Status: lint.Error, Details: "failed to parse extension OID"}
		}

		var critical bool
		if !ext.ReadOptionalASN1Boolean(&critical, cryptobyte_asn1.BOOLEAN, false) {
			return &lint.LintResult{Status: lint.Error, Details: "failed to parse extension criticality"}
		}

		var value cryptobyte.String
		if !ext.ReadASN1(&value, cryptobyte_asn1.OCTET_STRING) {
			return &lint.LintResult{Status: lint.Error, Details: "failed to parse extension value"}
		}

		if extnID.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}) {
			// basicConstraints is "Critical, with cA set to true".
			if !critical {
				return &lint.LintResult{Status: lint.Error, Details: "basicConstraints extension is not critical"}
			}

			var basicConstraints cryptobyte.String
			if !value.ReadASN1(&basicConstraints, cryptobyte_asn1.SEQUENCE) {
				return &lint.LintResult{Status: lint.Error, Details: "failed to parse basicConstraints"}
			}

			var ca bool
			if !basicConstraints.ReadASN1Boolean(&ca) {
				return &lint.LintResult{Status: lint.Error, Details: "failed to parse basicConstraints cA"}
			}

			if !ca {
				return &lint.LintResult{Status: lint.Error, Details: "basicConstraints cA is not true"}
			}

		} else if extnID.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}) {
			// keyUsage is "Critical, with the keyCertSign and cRLSign bits set".
			if !critical {
				return &lint.LintResult{Status: lint.Error, Details: "keyUsage extension is not critical"}
			}

			var keyUsage asn1.BitString
			if !value.ReadASN1BitString(&keyUsage) {
				return &lint.LintResult{Status: lint.Error, Details: "failed to parse keyUsage bits"}
			}

			for i := range 9 {
				switch i {
				case 5:
					if keyUsage.At(i) == 0 {
						return &lint.LintResult{Status: lint.Error, Details: "keyUsage does not assert keyCertSign"}
					}
				case 6:
					if keyUsage.At(i) == 0 {
						return &lint.LintResult{Status: lint.Error, Details: "keyUsage does not assert cRLSign"}
					}
				default:
					if keyUsage.At(i) == 1 {
						return &lint.LintResult{Status: lint.Error, Details: "unexpected keyUsage bit set"}
					}
				}
			}

		} else if extnID.Equal(asn1.ObjectIdentifier{2, 5, 29, 14}) {
			// subjectKeyIdentifier is "a truncated hash of the subjectPublicKey, per
			// Section 2(1) of RFC 7093".
			if critical {
				return &lint.LintResult{Status: lint.Error, Details: "subjectKeyIdentifier extension is critical"}
			}

			var subjectKeyIdentifier cryptobyte.String
			if !value.ReadASN1(&subjectKeyIdentifier, cryptobyte_asn1.SEQUENCE) {
				return &lint.LintResult{Status: lint.Error, Details: "failed to parse subjectKeyIdentifier"}
			}

			var keyIdentifier cryptobyte.String
			if !subjectKeyIdentifier.ReadASN1(&keyIdentifier, cryptobyte_asn1.Tag(0).ContextSpecific()) {
				return &lint.LintResult{Status: lint.Error, Details: "failed to parse keyIdentifier"}
			}

			keyHash := sha256.Sum256(subjectPublicKey.Bytes)
			if !bytes.Equal(keyHash[:20], keyIdentifier) {
				return &lint.LintResult{Status: lint.Error, Details: "incorrect subjectKeyIdentifier"}
			}

		} else {
			// Other extensions are "Not present".
			return &lint.LintResult{Status: lint.Error, Details: "unexpected extension"}
		}
	}

	if !extensionsSequence.Empty() {
		return &lint.LintResult{Status: lint.Error, Details: "too many extensions"}
	}

	// signatureAlgorithm is "Byte-for-byte identical to the tbsCertificate.signature".
	var signatureAlgorithm cryptobyte.String
	if !certificate.ReadASN1(&signatureAlgorithm, cryptobyte_asn1.OBJECT_IDENTIFIER) {
		return &lint.LintResult{Status: lint.Error, Details: "failed to parse signatureAlgorithm"}
	}

	if !bytes.Equal(signatureAlgorithm, signature) {
		return &lint.LintResult{Status: lint.Error, Details: "signatureAlgorithm is not identical to signature"}
	}

	return &lint.LintResult{Status: lint.Pass}
}
