package cpcps

// This file contains constants and parsing utilities shared by the lints which
// enforce the certificate profiles found in Section 7.1 of our CP/CPS. Only
// mechanical helpers (extracting bytes, computing hashes, constructing
// results) live here: every actual profile check is written out inline in the
// lint which enforces it, so that each lint can be read top-to-bottom against
// the text of the CP/CPS, and so that the profiles can diverge independently.

import (
	"encoding/pem"
	"fmt"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zlint/v3/lint"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	// The AlgorithmIdentifier encodings specified by Section 7.1.3.2 of the
	// Baseline Requirements, which Section 7.1.3.2 of our CP/CPS incorporates
	// by reference.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1115-L1117
	brSignatureAlgorithmIdentifiers = map[string]bool{
		// sha256WithRSAEncryption
		"300d06092a864886f70d01010b0500": true,
		// sha384WithRSAEncryption
		"300d06092a864886f70d01010c0500": true,
		// sha512WithRSAEncryption
		"300d06092a864886f70d01010d0500": true,
		// ecdsa-with-SHA256
		"300a06082a8648ce3d040302": true,
		// ecdsa-with-SHA384
		"300a06082a8648ce3d040303": true,
		// ecdsa-with-SHA512
		"300a06082a8648ce3d040304": true,
	}

	// The SubjectPublicKeyInfo AlgorithmIdentifier encodings specified by
	// Section 7.1.3.1 of the Baseline Requirements, which Section 7.1.3.1 of
	// our CP/CPS incorporates by reference.
	// https://github.com/letsencrypt/cp-cps/blob/6adcd83ff21e9571a39339048364edd6ba34ed39/CP-CPS.md?plain=1#L1111-L1113
	spkiAlgorithmRSA  = "300d06092a864886f70d0101010500"
	spkiAlgorithmP256 = "301306072a8648ce3d020106082a8648ce3d030107"
	spkiAlgorithmP384 = "301006072a8648ce3d020106052b81040022"
	spkiAlgorithmP521 = "301006072a8648ce3d020106052b81040023"

	// Extension OIDs used by the profile lints.
	authorityInformationAccessOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	authorityKeyIdentifierOID     = asn1.ObjectIdentifier{2, 5, 29, 35}
	basicConstraintsOID           = asn1.ObjectIdentifier{2, 5, 29, 19}
	certificatePoliciesOID        = asn1.ObjectIdentifier{2, 5, 29, 32}
	crlDistributionPointsOID      = asn1.ObjectIdentifier{2, 5, 29, 31}
	extKeyUsageOID                = asn1.ObjectIdentifier{2, 5, 29, 37}
	keyUsageOID                   = asn1.ObjectIdentifier{2, 5, 29, 15}
	subjectAltNameOID             = asn1.ObjectIdentifier{2, 5, 29, 17}
	subjectKeyIdentifierOID       = asn1.ObjectIdentifier{2, 5, 29, 14}
	sctListOID                    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

	// The Baseline Requirements Domain Validated Reserved Policy Identifier.
	domainValidatedOID = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}

	// Subject attribute type OIDs.
	commonNameOID = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// Keys within the shared configuration stanza. These must match the toml
// tags on IssuingCAConfig's fields, and are exported so that the linter
// package can emit configuration using these keys.
const (
	// GlobalConfigNamespace is the name of the TOML stanza from which
	// IssuingCAConfig is deserialized. It must match the namespace of zlint's
	// lint.Global higher-scoped configuration, which IssuingCAConfig embeds.
	GlobalConfigNamespace = "Global"
	// IssuerCertificateConfigKey configures the Issuing CA's certificate.
	IssuerCertificateConfigKey = "issuer_certificate"
	// ExistingCertificateConfigKey configures the pre-existing certificate of
	// a CA being cross-signed.
	ExistingCertificateConfigKey = "existing_certificate"
)

// globalNamespace aliases zlint's lint.Global so that IssuingCAConfig can
// embed it under an unexported field name. The promoted (unexported)
// namespace method is what routes deserialization of IssuingCAConfig to the
// shared [Global] stanza, via zlint's "higher-scoped configuration"
// mechanism; the unexported field name makes zlint's reflection-based config
// resolver skip the embedded field itself, which it could not deserialize.
type globalNamespace = lint.Global //nolint:unused // Used in SharedConfig.

// SharedConfig is the lint configuration shared by every CP/CPS profile
// lint. Rather than each lint carrying an identical stanza of its own, all of
// them declare a pointer to this struct, which zlint fills from the single
// shared [Global] stanza of the lint configuration.
type SharedConfig struct {
	globalNamespace //nolint:unused // Used by zlint, not by us.
	// IssuerCertificatePEM must hold the PEM encoding of the Issuing CA's
	// certificate, so that the profile rows requiring byte-for-byte
	// correspondence with the Issuing CA can be enforced. If it is not
	// configured, the CP/CPS profile lints fail.
	IssuerCertificatePEM string `toml:"issuer_certificate" comment:"The PEM encoding of the Issuing CA's certificate."`
	// ExistingCertificatePEM must hold the PEM encoding of the existing CA
	// Certificate upon which a cross-certificate confers a second issuance
	// path. It is read only by the cross-certified subordinate CA profile
	// lint, and only the ceremony tool ever configures it, because only the
	// ceremony tool issues cross-certificates.
	ExistingCertificatePEM string `toml:"existing_certificate" comment:"The PEM encoding of the existing CA Certificate being cross-signed."`
}

// issuerPEM returns the configured Issuing CA certificate PEM, or the empty
// string if the receiver was never configured.
func (c *SharedConfig) issuerPEM() string {
	if c == nil {
		return ""
	}
	return c.IssuerCertificatePEM
}

// existingPEM returns the configured existing CA certificate PEM, or the
// empty string if the receiver was never configured.
func (c *SharedConfig) existingPEM() string {
	if c == nil {
		return ""
	}
	return c.ExistingCertificatePEM
}

// errResult is a convenience constructor for a failing lint result.
func errResult(details string) *lint.LintResult {
	return &lint.LintResult{Status: lint.Error, Details: details}
}

// fatalResult is a convenience constructor for a fatal lint result, used when
// the lint's own configuration is unusable.
func fatalResult(details string) *lint.LintResult {
	return &lint.LintResult{Status: lint.Fatal, Details: details}
}

// getOuterSignatureAlgorithm returns the DER bytes (including tag and length)
// of the signatureAlgorithm field of the outer Certificate sequence.
func getOuterSignatureAlgorithm(der []byte) ([]byte, error) {
	input := cryptobyte.String(der)
	var certificate cryptobyte.String
	if !input.ReadASN1(&certificate, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to parse certificate")
	}
	if !certificate.SkipASN1(cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to parse tbsCertificate")
	}
	var signatureAlgorithm cryptobyte.String
	if !certificate.ReadASN1Element(&signatureAlgorithm, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to parse signatureAlgorithm")
	}
	return signatureAlgorithm, nil
}

// getExtension returns the extension with the given OID, or nil if absent.
func getExtension(c *x509.Certificate, oid asn1.ObjectIdentifier) *pkix.Extension {
	for _, ext := range c.Extensions {
		if ext.Id.Equal(oid) {
			return &pkix.Extension{Id: ext.Id, Critical: ext.Critical, Value: ext.Value}
		}
	}
	return nil
}

// parseConfiguredCertificate parses a PEM certificate provided via lint
// configuration. It returns a nil certificate and nil error if the
// configuration string is empty; lints which require the certificate must
// treat that as a failure.
func parseConfiguredCertificate(pemBytes string) (*x509.Certificate, error) {
	if pemBytes == "" {
		return nil, nil
	}
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode configured PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse configured certificate: %w", err)
	}
	return cert, nil
}
