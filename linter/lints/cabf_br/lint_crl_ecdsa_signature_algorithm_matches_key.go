package cabfbr

import (
	"bytes"
	encoding_asn1 "encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type crlECDSASignatureAlgorithmMatchesKey struct{}

/************************************************
Baseline Requirements: 7.1.3.2.2:
If the signing key is P-256, the signature MUST use ECDSA with SHA-256. When
encoded, the AlgorithmIdentifier MUST be byte-for-byte identical with the
following hex-encoded bytes: 300a06082a8648ce3d040302.

If the signing key is P-384, the signature MUST use ECDSA with SHA-384. When
encoded, the AlgorithmIdentifier MUST be byte-for-byte identical with the
following hex-encoded bytes: 300a06082a8648ce3d040303.

If the signing key is P-521, the signature MUST use ECDSA with SHA-512. When
encoded, the AlgorithmIdentifier MUST be byte-for-byte identical with the
following hex-encoded bytes: 300a06082a8648ce3d040304.

Mozilla Root Store Policy 5.1.2 imposes the same requirement on all signatures
produced by root and intermediate ECDSA keys.

zlint's e_mp_ecdsa_signature_encoding_correct enforces this for certificates,
but nothing enforces it for CRLs. A CRL lint is not given the issuer's
certificate, so we infer the signing key's curve from the signature itself:
r and s are both reduced modulo the curve order, so a P-256 signature never
has an r or s longer than 256 bits, and the chance of a P-384 (or P-521)
signature having both r and s that short is about 2^-256 (or 2^-274).
************************************************/

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_crl_ecdsa_signature_algorithm_matches_key",
			Description:   "CRLs signed by ECDSA keys must use the signature AlgorithmIdentifier which corresponds to the signing key's curve",
			Citation:      "BRs: 7.1.3.2.2",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_1_7_1_Date,
		},
		Lint: NewCrlECDSASignatureAlgorithmMatchesKey,
	})
}

func NewCrlECDSASignatureAlgorithmMatchesKey() lint.RevocationListLintInterface {
	return &crlECDSASignatureAlgorithmMatchesKey{}
}

// oidECDSASignatureAlgorithms is the arc under which all of the
// ecdsa-with-SHA* signature algorithms live (RFC 5758, Section 3.2).
var oidECDSASignatureAlgorithms = encoding_asn1.ObjectIdentifier{1, 2, 840, 10045, 4}

func (l *crlECDSASignatureAlgorithmMatchesKey) CheckApplies(c *x509.RevocationList) bool {
	_, outerAlg, err := crlSignatureAlgorithms(c.Raw)
	if err != nil {
		// Apply, so that Execute reports the parsing error.
		return true
	}
	input := cryptobyte.String(outerAlg)
	var algID cryptobyte.String
	var oid encoding_asn1.ObjectIdentifier
	if !input.ReadASN1(&algID, cryptobyte_asn1.SEQUENCE) || !algID.ReadASN1ObjectIdentifier(&oid) {
		return true
	}
	return len(oid) > len(oidECDSASignatureAlgorithms) &&
		oid[:len(oidECDSASignatureAlgorithms)].Equal(oidECDSASignatureAlgorithms)
}

func (l *crlECDSASignatureAlgorithmMatchesKey) Execute(c *x509.RevocationList) *lint.LintResult {
	tbsAlg, outerAlg, err := crlSignatureAlgorithms(c.Raw)
	if err != nil {
		return &lint.LintResult{Status: lint.Error, Details: err.Error()}
	}

	bitLen, err := ecdsaSignatureBitLen(c.Signature)
	if err != nil {
		return &lint.LintResult{Status: lint.Error, Details: err.Error()}
	}

	var curve, expected string
	switch {
	case bitLen <= 256:
		curve, expected = "P-256", "300a06082a8648ce3d040302"
	case bitLen <= 384:
		curve, expected = "P-384", "300a06082a8648ce3d040303"
	case bitLen <= 521:
		curve, expected = "P-521", "300a06082a8648ce3d040304"
	default:
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("ECDSA signature component is %d bits, which does not correspond to an allowed curve", bitLen),
		}
	}

	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		return &lint.LintResult{Status: lint.Error, Details: err.Error()}
	}
	if !bytes.Equal(tbsAlg, expectedBytes) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("CRL signature field is %x, but signing key on %s requires %s", tbsAlg, curve, expected),
		}
	}
	// zcrypto currently refuses to parse a CRL whose signature and
	// signatureAlgorithm fields differ, but check both rather than rely on it.
	if !bytes.Equal(outerAlg, expectedBytes) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("CRL signatureAlgorithm field is %x, but signing key on %s requires %s", outerAlg, curve, expected),
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// crlSignatureAlgorithms returns the DER bytes (including tag and length) of
// both the tbsCertList.signature field and the outer signatureAlgorithm field
// of the given CertificateList.
//
//	RFC 5280: 5.1
//	CertificateList  ::=  SEQUENCE  {
//	     tbsCertList          TBSCertList,
//	     signatureAlgorithm   AlgorithmIdentifier,
//	     signatureValue       BIT STRING  }
//
//	TBSCertList  ::=  SEQUENCE  {
//	     version                 Version OPTIONAL,
//	     signature               AlgorithmIdentifier,
//	     ...
func crlSignatureAlgorithms(der []byte) ([]byte, []byte, error) {
	input := cryptobyte.String(der)
	var certList cryptobyte.String
	if !input.ReadASN1(&certList, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, fmt.Errorf("failed to parse CertificateList")
	}
	var tbsCertList cryptobyte.String
	if !certList.ReadASN1(&tbsCertList, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, fmt.Errorf("failed to parse tbsCertList")
	}
	if !tbsCertList.SkipOptionalASN1(cryptobyte_asn1.INTEGER) {
		return nil, nil, fmt.Errorf("failed to parse tbsCertList version")
	}
	var tbsAlg cryptobyte.String
	if !tbsCertList.ReadASN1Element(&tbsAlg, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, fmt.Errorf("failed to parse tbsCertList signature")
	}
	var outerAlg cryptobyte.String
	if !certList.ReadASN1Element(&outerAlg, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, fmt.Errorf("failed to parse signatureAlgorithm")
	}
	return tbsAlg, outerAlg, nil
}

// ecdsaSignatureBitLen returns the bit length of the longer of r and s in the
// given DER-encoded ECDSA-Sig-Value (RFC 5480, Appendix A).
func ecdsaSignatureBitLen(sig []byte) (int, error) {
	input := cryptobyte.String(sig)
	var inner cryptobyte.String
	r, s := new(big.Int), new(big.Int)
	if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) || !input.Empty() ||
		!inner.ReadASN1Integer(r) || !inner.ReadASN1Integer(s) || !inner.Empty() {
		return 0, fmt.Errorf("failed to parse ECDSA signature")
	}
	return max(r.BitLen(), s.BitLen()), nil
}
