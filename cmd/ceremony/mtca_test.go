package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	casn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/letsencrypt/boulder/core/reloid"
)

// mtcaSubjectHex is the DER encoding of the Subject of an MTCA with CA ID
// 32473.1. The attribute value (0d0481fd5901) is the example given in
// draft-ietf-plants-merkle-tree-certs-07, Section 5.1.
//
//	30 14                          RDNSequence
//	  31 12                        RelativeDistinguishedName
//	    30 10                      AttributeTypeAndValue
//	      06 08 2b06010505071903   id-rdna-trustAnchorID (1.3.6.1.5.5.7.25.3)
//	      0d 04 81fd5901           RELATIVE-OID 32473.1
const mtcaSubjectHex = "30143112301006082b060105050719030d0481fd5901"

// mldsa44AlgIDHex is the DER encoding of the ML-DSA-44 AlgorithmIdentifier,
// which the Chrome Quantum-resistant Root Program Policy, Section 2.4.3.1,
// requires byte-for-byte in MTC CA certificates.
const mldsa44AlgIDHex = "300b0609608648016503040311"

// writePubKey writes pub, PEM-encoded, to a file in dir. It returns the file's
// path.
func writePubKey(t *testing.T, dir string, pub crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshaling test key: %s", err)
	}
	keyPath := path.Join(dir, "mtca.pubkey.pem")
	err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0644)
	if err != nil {
		t.Fatalf("writing test key: %s", err)
	}
	return keyPath
}

// writeMLDSAPubKey generates an ML-DSA-44 key and writes its PEM-encoded public
// key to a file in dir. It returns the public key and the file's path.
func writeMLDSAPubKey(t *testing.T, dir string) (*mldsa.PublicKey, string) {
	t.Helper()
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("generating ML-DSA-44 test key: %s", err)
	}
	return priv.PublicKey(), writePubKey(t, dir, priv.PublicKey())
}

// testMTCAConfig returns a valid mtcaConfig which reads its public key from
// pubKeyPath and writes its certificate into dir.
func testMTCAConfig(pubKeyPath, dir string) mtcaConfig {
	var config mtcaConfig
	config.CeremonyType = "mtca"
	config.Inputs.PublicKeyPath = pubKeyPath
	config.Outputs.CertificatePath = path.Join(dir, "mtca.cert.pem")
	config.CertProfile.PolicyURL = "https://github.com/letsencrypt/cp-cps/blob/v0.1/CP-CPS.md#subsection"
	config.CertProfile.MTCAID = "32473.1"
	config.CertProfile.NotBefore = "2026-01-01 00:00:00"
	config.CertProfile.NotAfter = "2035-12-31 23:59:59"
	config.CertProfile.TlogPrefix = "https://example.com/tlog"
	return config
}

func TestMTCAConfigValidate(t *testing.T) {
	dir := t.TempDir()
	existingPath := path.Join(dir, "existing.pem")
	err := os.WriteFile(existingPath, []byte("hi"), 0644)
	if err != nil {
		t.Fatalf("writing existing file: %s", err)
	}

	testCases := []struct {
		name    string
		mutate  func(*mtcaConfig)
		wantErr string
	}{
		{
			name:   "valid",
			mutate: func(*mtcaConfig) {},
		},
		{
			name:    "no public-key-path",
			mutate:  func(c *mtcaConfig) { c.Inputs.PublicKeyPath = "" },
			wantErr: "inputs.public-key-path is required",
		},
		{
			name:    "no certificate-path",
			mutate:  func(c *mtcaConfig) { c.Outputs.CertificatePath = "" },
			wantErr: "outputs.certificate-path is required",
		},
		{
			name:    "certificate-path already exists",
			mutate:  func(c *mtcaConfig) { c.Outputs.CertificatePath = existingPath },
			wantErr: "already exists",
		},
		{
			name:    "no policy-url",
			mutate:  func(c *mtcaConfig) { c.CertProfile.PolicyURL = "" },
			wantErr: "policy-url is required",
		},
		{
			name: "policy-url not a CPS subsection",
			mutate: func(c *mtcaConfig) {
				c.CertProfile.PolicyURL = "https://github.com/letsencrypt/cp-cps/blob/main/CP-CPS.md"
			},
			wantErr: "policy-url must point to a specific subsection",
		},
		{
			name:    "no mtcaid",
			mutate:  func(c *mtcaConfig) { c.CertProfile.MTCAID = "" },
			wantErr: "mtcaid is required",
		},
		{
			name:    "no not-before",
			mutate:  func(c *mtcaConfig) { c.CertProfile.NotBefore = "" },
			wantErr: "not-before is required",
		},
		{
			name:    "no not-after",
			mutate:  func(c *mtcaConfig) { c.CertProfile.NotAfter = "" },
			wantErr: "not-after is required",
		},
		{
			name:    "no tlog-prefix",
			mutate:  func(c *mtcaConfig) { c.CertProfile.TlogPrefix = "" },
			wantErr: "tlog-prefix is required",
		},
		{
			name:    "tlog-prefix ends with a slash",
			mutate:  func(c *mtcaConfig) { c.CertProfile.TlogPrefix = "https://example.com/tlog/" },
			wantErr: "tlog-prefix must not end with a slash",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// validate doesn't read the public key, so it doesn't need to exist.
			config := testMTCAConfig(path.Join(dir, "pubkey.pem"), dir)
			tc.mutate(&config)

			err := config.validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validate() = %v, want success", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validate() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestMTCATemplate(t *testing.T) {
	dir := t.TempDir()
	_, pubKeyPath := writeMLDSAPubKey(t, dir)
	config := testMTCAConfig(pubKeyPath, dir)

	tmpl, err := config.template()
	if err != nil {
		t.Fatalf("template() = %v, want success", err)
	}

	// The serial has 128 random bits, behind a 0x01 byte which keeps it from
	// being shortened by leading zeroes.
	serialBytes := tmpl.SerialNumber.Bytes()
	if len(serialBytes) != 17 || serialBytes[0] != 0x01 {
		t.Errorf("template() got serial %x, want 17 bytes starting with 01", serialBytes)
	}
	tmpl2, err := config.template()
	if err != nil {
		t.Fatalf("template() = %v, want success", err)
	}
	if tmpl.SerialNumber.Cmp(tmpl2.SerialNumber) == 0 {
		t.Errorf("template() returned the same serial %x twice", serialBytes)
	}

	subject, err := asn1.Marshal(tmpl.Subject.ToRDNSequence())
	if err != nil {
		t.Fatalf("marshaling subject: %s", err)
	}
	if hex.EncodeToString(subject) != mtcaSubjectHex {
		t.Errorf("template() got subject %x, want %s", subject, mtcaSubjectHex)
	}

	wantNotBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if !tmpl.NotBefore.Equal(wantNotBefore) {
		t.Errorf("template() got NotBefore %s, want %s", tmpl.NotBefore, wantNotBefore)
	}
	wantNotAfter := time.Date(2035, 12, 31, 23, 59, 59, 0, time.UTC)
	if !tmpl.NotAfter.Equal(wantNotAfter) {
		t.Errorf("template() got NotAfter %s, want %s", tmpl.NotAfter, wantNotAfter)
	}

	// draft-ietf-plants-merkle-tree-certs-07, Section 5.5: basic constraints
	// MUST set cA, and key usage MUST assert keyCertSign. CQRP Policy, Section
	// 2.4.3.1: key usage MUST also assert cRLSign.
	if !tmpl.BasicConstraintsValid || !tmpl.IsCA {
		t.Errorf("template() got BasicConstraintsValid=%t IsCA=%t, want both true",
			tmpl.BasicConstraintsValid, tmpl.IsCA)
	}
	if tmpl.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("template() got KeyUsage %#x, want CertSign|CRLSign", tmpl.KeyUsage)
	}
	// Baseline Requirements, Section 7.1.2.1.2: Root CA certificates MUST NOT
	// have an extended key usage extension.
	if len(tmpl.ExtKeyUsage) != 0 || len(tmpl.UnknownExtKeyUsage) != 0 {
		t.Errorf("template() got ExtKeyUsage %v and UnknownExtKeyUsage %v, want neither",
			tmpl.ExtKeyUsage, tmpl.UnknownExtKeyUsage)
	}

	// draft-ietf-plants-merkle-tree-certs-07, Section 5.5: the subject key
	// identifier SHOULD be the binary representation of the CA ID.
	mtcaID, err := reloid.FromString("32473.1")
	if err != nil {
		t.Fatalf("parsing MTCA ID: %s", err)
	}
	if !bytes.Equal(tmpl.SubjectKeyId, mtcaID.Bytes()) {
		t.Errorf("template() got SubjectKeyId %x, want CA ID %x", tmpl.SubjectKeyId, mtcaID.Bytes())
	}

	wantExtIDs := []asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7, 1, 38},
		{1, 3, 6, 1, 4, 1, 64829, 2, 2},
	}
	var gotExtIDs []asn1.ObjectIdentifier
	for _, ext := range tmpl.ExtraExtensions {
		gotExtIDs = append(gotExtIDs, ext.Id)
	}
	if !slices.EqualFunc(gotExtIDs, wantExtIDs, asn1.ObjectIdentifier.Equal) {
		t.Errorf("template() got ExtraExtensions %v, want %v", gotExtIDs, wantExtIDs)
	}
}

func TestMTCATemplateErrors(t *testing.T) {
	dir := t.TempDir()
	_, pubKeyPath := writeMLDSAPubKey(t, dir)

	// The validity period may be at most 3660 days, counting both the
	// not-before and not-after seconds.
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	maxNotAfter := notBefore.Add(3660*24*time.Hour - time.Second)

	testCases := []struct {
		name    string
		mutate  func(*mtcaConfig)
		wantErr string
	}{
		{
			name: "validity is exactly 3660 days",
			mutate: func(c *mtcaConfig) {
				c.CertProfile.NotBefore = notBefore.Format(time.DateTime)
				c.CertProfile.NotAfter = maxNotAfter.Format(time.DateTime)
			},
		},
		{
			name: "validity is longer than 3660 days",
			mutate: func(c *mtcaConfig) {
				c.CertProfile.NotBefore = notBefore.Format(time.DateTime)
				c.CertProfile.NotAfter = maxNotAfter.Add(time.Second).Format(time.DateTime)
			},
			wantErr: "validity period is more than 3660 days",
		},
		{
			name:    "mtcaid not a relative oid",
			mutate:  func(c *mtcaConfig) { c.CertProfile.MTCAID = "32473..1" },
			wantErr: "invalid mtcaid relative oid",
		},
		{
			name:    "not-before not a datetime",
			mutate:  func(c *mtcaConfig) { c.CertProfile.NotBefore = "2026-01-01" },
			wantErr: "invalid not-before",
		},
		{
			name:    "not-after not a datetime",
			mutate:  func(c *mtcaConfig) { c.CertProfile.NotAfter = "2035-12-31" },
			wantErr: "invalid not-after",
		},
		{
			name:    "not-before after not-after",
			mutate:  func(c *mtcaConfig) { c.CertProfile.NotBefore = "2036-01-01 00:00:00" },
			wantErr: "not-before is after not-after",
		},
		{
			name:    "tlog-prefix not a url",
			mutate:  func(c *mtcaConfig) { c.CertProfile.TlogPrefix = "https://example.com/%zz" },
			wantErr: "invalid tlog-prefix url",
		},
		{
			name:    "tlog-prefix not https",
			mutate:  func(c *mtcaConfig) { c.CertProfile.TlogPrefix = "http://example.com/tlog" },
			wantErr: "tlog-prefix must be an https:// url",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := testMTCAConfig(pubKeyPath, dir)
			tc.mutate(&config)

			_, err := config.template()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("template() = %v, want success", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("template() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestMTCASubject(t *testing.T) {
	mtcaID, err := reloid.FromString("32473.1")
	if err != nil {
		t.Fatalf("parsing MTCA ID: %s", err)
	}
	der, err := asn1.Marshal(mtcaSubject(mtcaID).ToRDNSequence())
	if err != nil {
		t.Fatalf("marshaling subject: %s", err)
	}
	if hex.EncodeToString(der) != mtcaSubjectHex {
		t.Errorf("mtcaSubject() = %x, want %s", der, mtcaSubjectHex)
	}
}

func TestMTCAExtension(t *testing.T) {
	ext, err := mtcaExtension()
	if err != nil {
		t.Fatalf("mtcaExtension() = %v, want success", err)
	}
	if !ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 38}) {
		t.Errorf("mtcaExtension() got OID %s, want id-pe-mtcCertificationAuthority-SHA256", ext.Id)
	}
	if !ext.Critical {
		t.Errorf("mtcaExtension() got non-critical extension, want critical")
	}

	// draft-ietf-plants-merkle-tree-certs-07, Section 5.5:
	//
	//	MTCCertificationAuthority ::= SEQUENCE {
	//	    sigAlg    AlgorithmIdentifier{SIGNATURE-ALGORITHM, {...}},
	//	    minSerial INTEGER (mtcMinSerial..mtcMaxSerial),
	//	    maxSerial INTEGER (mtcMinSerial..mtcMaxSerial)
	//	}
	value := cryptobyte.String(ext.Value)
	var mtca, sigAlg cryptobyte.String
	if !value.ReadASN1(&mtca, casn1.SEQUENCE) || !value.Empty() {
		t.Fatalf("mtcaExtension() got value %x, want a single SEQUENCE", ext.Value)
	}
	if !mtca.ReadASN1Element(&sigAlg, casn1.SEQUENCE) {
		t.Fatalf("mtcaExtension() got value %x, want sigAlg AlgorithmIdentifier", ext.Value)
	}
	if hex.EncodeToString(sigAlg) != mldsa44AlgIDHex {
		t.Errorf("mtcaExtension() got sigAlg %x, want ML-DSA-44 %s", []byte(sigAlg), mldsa44AlgIDHex)
	}
	// ReadASN1Integer into a uint64 rejects negative values, and values above
	// mtcMaxSerial (2^64-1).
	var minSerial, maxSerial uint64
	if !mtca.ReadASN1Integer(&minSerial) {
		t.Fatalf("mtcaExtension() got value %x, want minSerial INTEGER", ext.Value)
	}
	if !mtca.ReadASN1Integer(&maxSerial) {
		t.Fatalf("mtcaExtension() got value %x, want maxSerial INTEGER", ext.Value)
	}
	if !mtca.Empty() {
		t.Errorf("mtcaExtension() got value %x, want nothing after maxSerial", ext.Value)
	}
	// Serial numbers are (log_number << 48) | index, and CQRP Policy, Section
	// 2.5.1.3, only trusts log numbers 1 through 5. So minSerial is index 0 of
	// log 1, and maxSerial is the last index of log 5.
	const wantMinSerial = 1 << 48
	const wantMaxSerial = 6<<48 - 1
	if minSerial != wantMinSerial || maxSerial != wantMaxSerial {
		t.Errorf("mtcaExtension() got minSerial %#x and maxSerial %#x, want %#x and %#x",
			minSerial, maxSerial, uint64(wantMinSerial), uint64(wantMaxSerial))
	}
}

func TestTlogPrefixExtension(t *testing.T) {
	prefix := "https://example.com/tlog"
	ext, err := tlogPrefixExtension(prefix)
	if err != nil {
		t.Fatalf("tlogPrefixExtension() = %v, want success", err)
	}
	if !ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 64829, 2, 2}) {
		t.Errorf("tlogPrefixExtension() got OID %s, want id-mtcTlogPrefixURLs", ext.Id)
	}
	if ext.Critical {
		t.Errorf("tlogPrefixExtension() got critical extension, want non-critical")
	}
	// MTCTlogPrefixURLs ::= SEQUENCE SIZE (1..MAX) OF IA5String
	want := append([]byte{0x30, 0x1a, 0x16, 0x18}, prefix...)
	if !bytes.Equal(ext.Value, want) {
		t.Errorf("tlogPrefixExtension() got value %x, want %x", ext.Value, want)
	}
}

func TestMTCACeremony(t *testing.T) {
	dir := t.TempDir()
	pubKey, pubKeyPath := writeMLDSAPubKey(t, dir)
	certPath := path.Join(dir, "mtca.cert.pem")

	config := fmt.Appendf(nil, `
ceremony-type: mtca
inputs:
  public-key-path: %s
outputs:
  certificate-path: %s
certificate-profile:
  policy-url: https://github.com/letsencrypt/cp-cps/blob/v0.1/CP-CPS.md#subsection
  mtcaid: 32473.1
  not-before: 2026-01-01 00:00:00
  not-after: 2035-12-31 23:59:59
  tlog-prefix: https://example.com/tlog
skip-lints:
  # CQRP Policy, Section 2.4.3.1, exempts MTC CA certificates from the BRs'
  # algorithm restrictions when using ML-DSA.
  - e_algorithm_identifier_improper_encoding
  - e_public_key_type_not_allowed
  - e_signature_algorithm_not_supported
  # draft-ietf-plants-merkle-tree-certs-07, Section 5.5, requires the subject
  # to be only the CA ID, as a RELATIVE-OID.
  - e_ca_common_name_missing
  - e_ca_country_name_missing
  - e_ca_organization_name_missing
  - e_subject_dn_not_printable_characters
  # RFC 9925, Section 3.3 says that unsigned certs should omit the AKID.
  - e_ext_authority_key_identifier_no_key_identifier
  # zlint treats the cert as a subordinate CA, because it's signed by a
  # throwaway key rather than its own (and zcrypto can't verify ML-DSA
  # signatures anyway), but it doesn't have to match that profile.
  - e_invalid_ca_certificate_policies
  - e_sub_ca_certificate_policies_missing
  - e_sub_ca_crl_distribution_points_missing
  - e_validity_period_greater_than_8_years
  - n_mp_allowed_eku
  - n_sub_ca_eku_missing
  - w_sub_ca_aia_missing
  # CA cosigner keys sign subtrees and checkpoints, not OCSP responses.
  - n_ca_digital_signature_not_set
`, pubKeyPath, certPath)

	err := mtcaCeremony(config)
	if err != nil {
		t.Fatalf("mtcaCeremony() = %v, want success", err)
	}

	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("reading certificate: %s", err)
	}
	block, rest := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatalf("mtcaCeremony() wrote %q, want a single PEM CERTIFICATE", pemBytes)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing certificate: %s", err)
	}

	// draft-ietf-plants-merkle-tree-certs-07, Section 5.5: the certificate
	// SHOULD be an RFC 9925 unsigned certificate, which has an empty signature
	// and an algorithm (id-alg-unsigned) which crypto/x509 doesn't recognize.
	if len(cert.Signature) != 0 || cert.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		t.Errorf("mtcaCeremony() wrote certificate with %s signature %x, want unsigned",
			cert.SignatureAlgorithm, cert.Signature)
	}
	// RFC 9925, Section 3.3: unsigned certificates SHOULD omit the authority
	// key identifier.
	if len(cert.AuthorityKeyId) != 0 {
		t.Errorf("mtcaCeremony() wrote certificate with AuthorityKeyId %x, want none", cert.AuthorityKeyId)
	}
	// RFC 9925, Section 3.2: the issuer MAY be the subject, as a placeholder.
	if hex.EncodeToString(cert.RawSubject) != mtcaSubjectHex {
		t.Errorf("mtcaCeremony() wrote certificate with subject %x, want %s", cert.RawSubject, mtcaSubjectHex)
	}
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		t.Errorf("mtcaCeremony() wrote certificate with issuer %x, want same as subject", cert.RawIssuer)
	}

	if !pubKey.Equal(cert.PublicKey) {
		t.Errorf("mtcaCeremony() wrote certificate with a different public key than the input")
	}
	spki := cryptobyte.String(cert.RawSubjectPublicKeyInfo)
	var spkiInner, spkiAlg cryptobyte.String
	if !spki.ReadASN1(&spkiInner, casn1.SEQUENCE) || !spkiInner.ReadASN1Element(&spkiAlg, casn1.SEQUENCE) {
		t.Fatalf("parsing SubjectPublicKeyInfo %x", cert.RawSubjectPublicKeyInfo)
	}
	if hex.EncodeToString(spkiAlg) != mldsa44AlgIDHex {
		t.Errorf("mtcaCeremony() wrote certificate with key algorithm %x, want ML-DSA-44 %s", []byte(spkiAlg), mldsa44AlgIDHex)
	}

	// CQRP Policy, Section 2.4.3.1: key usage MUST be critical.
	keyUsageOID := asn1.ObjectIdentifier{2, 5, 29, 15}
	if !slices.ContainsFunc(cert.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(keyUsageOID) && e.Critical }) {
		t.Errorf("mtcaCeremony() wrote certificate without a critical key usage extension")
	}

	mtcaExt, err := mtcaExtension()
	if err != nil {
		t.Fatalf("mtcaExtension() = %v, want success", err)
	}
	tlogPrefixExt, err := tlogPrefixExtension("https://example.com/tlog")
	if err != nil {
		t.Fatalf("tlogPrefixExtension() = %v, want success", err)
	}
	for _, want := range []pkix.Extension{mtcaExt, tlogPrefixExt} {
		found := slices.ContainsFunc(cert.Extensions, func(got pkix.Extension) bool {
			return got.Id.Equal(want.Id) && got.Critical == want.Critical && bytes.Equal(got.Value, want.Value)
		})
		if !found {
			t.Errorf("mtcaCeremony() wrote certificate without extension %s", want.Id)
		}
	}
}

func TestMTCACeremonyBadConfig(t *testing.T) {
	err := mtcaCeremony([]byte("ceremony-type: mtca\nunknown-field: true\n"))
	if err == nil || !strings.Contains(err.Error(), "failed to parse config") {
		t.Errorf("mtcaCeremony() = %v, want parse error", err)
	}

	err = mtcaCeremony([]byte("ceremony-type: mtca\n"))
	if err == nil || !strings.Contains(err.Error(), "invalid config") {
		t.Errorf("mtcaCeremony() = %v, want validation error", err)
	}
}

// CQRP Policy, Section 2.4.3.1: MTC CA keys MUST be ML-DSA-44.
func TestMTCACeremonyBadKey(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA test key: %s", err)
	}
	mldsa65Key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("generating ML-DSA-65 test key: %s", err)
	}

	testCases := []struct {
		name string
		pub  crypto.PublicKey
	}{
		{name: "ECDSA P-256", pub: ecdsaKey.Public()},
		{name: "ML-DSA-65", pub: mldsa65Key.PublicKey()},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			pubKeyPath := writePubKey(t, dir, tc.pub)
			certPath := path.Join(dir, "mtca.cert.pem")

			config := fmt.Appendf(nil, `
ceremony-type: mtca
inputs:
  public-key-path: %s
outputs:
  certificate-path: %s
certificate-profile:
  policy-url: https://github.com/letsencrypt/cp-cps/blob/v0.1/CP-CPS.md#subsection
  mtcaid: 32473.1
  not-before: 2026-01-01 00:00:00
  not-after: 2035-12-31 23:59:59
  tlog-prefix: https://example.com/tlog
`, pubKeyPath, certPath)

			err := mtcaCeremony(config)
			if err == nil || !strings.Contains(err.Error(), "pubkey does not meet policy") {
				t.Fatalf("mtcaCeremony() = %v, want key policy error", err)
			}
			_, err = os.Stat(certPath)
			if !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("mtcaCeremony() wrote a certificate for a rejected key (stat error: %v)", err)
			}
		})
	}
}
