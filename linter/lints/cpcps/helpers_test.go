package cpcps

// Helpers for building test certificates for the CP/CPS profile lints. The
// certificates are constructed with crypto/x509 and then re-parsed with
// zcrypto, mirroring how the linter package produces the certificates that
// these lints run against in production.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	zx509 "github.com/zmap/zcrypto/x509"
	zpkix "github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

// testKey generates an ECDSA key on the given curve.
func testKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generating test key: %s", err)
	}
	return key
}

// testSerial returns a positive integer occupying exactly nBytes bytes.
func testSerial(t *testing.T, nBytes int) *big.Int {
	t.Helper()
	bytes := make([]byte, nBytes)
	_, err := rand.Read(bytes)
	if err != nil {
		t.Fatalf("generating test serial: %s", err)
	}
	// Force the first byte into [0x40, 0x7f] so the value occupies exactly
	// nBytes bytes and its DER encoding needs no leading zero byte.
	bytes[0] = bytes[0]&0x3f | 0x40
	return new(big.Int).SetBytes(bytes)
}

// testRFC7093SKID computes a key identifier per RFC 7093 Section 2(1): the
// leftmost 160 bits of the SHA-256 hash of the subjectPublicKey BIT STRING
// contents.
func testRFC7093SKID(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	spkiDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshalling public key: %s", err)
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(spkiDER, &spki)
	if err != nil {
		t.Fatalf("unmarshalling public key: %s", err)
	}
	hash := sha256.Sum256(spki.PublicKey.Bytes)
	return hash[:20]
}

// testParseZCert parses DER into a zcrypto certificate.
func testParseZCert(t *testing.T, der []byte) *zx509.Certificate {
	t.Helper()
	cert, err := zx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate with zcrypto: %s", err)
	}
	return cert
}

// testRootTemplate returns a template matching the Root CA Certificate
// Profile from CP/CPS Section 7.1.
func testRootTemplate(t *testing.T, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	notBefore := time.Date(2025, time.October, 1, 0, 0, 0, 0, time.UTC)
	return &x509.Certificate{
		SerialNumber: testSerial(t, 16),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"ISRG"},
			CommonName:   "ISRG Root X99",
		},
		NotBefore: notBefore,
		// 3660 days, inclusive of the final second.
		NotAfter:              notBefore.AddDate(0, 0, 3660).Add(-time.Second),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          testRFC7093SKID(t, pub),
	}
}

// testIntermediateTemplate returns a template approximating the TLS Subordinate CA
// Certificate Profile from CP/CPS Section 7.1.
func testIntermediateTemplate(t *testing.T, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	dvOID, _ := x509.OIDFromASN1OID(asn1.ObjectIdentifier(util.BRDomainValidatedOID))
	notBefore := time.Date(2025, time.November, 1, 0, 0, 0, 0, time.UTC)
	return &x509.Certificate{
		SerialNumber: testSerial(t, 16),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Let's Encrypt"},
			CommonName:   "E99",
		},
		NotBefore: notBefore,
		// 1098 days, inclusive of the final second.
		NotAfter:              notBefore.AddDate(0, 0, 1098).Add(-time.Second),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Policies:              []x509.OID{dvOID},
		IssuingCertificateURL: []string{"http://x99.i.lencr.org/"},
		CRLDistributionPoints: []string{"http://x99.c.lencr.org/1.crl"},
		SubjectKeyId:          testRFC7093SKID(t, pub),
	}
}

// testSCT returns the RFC 6962 serialization of a fake (unverifiable) v1 SCT
// from the log with the given ID.
func testSCT(logID [32]byte) []byte {
	var sct []byte
	sct = append(sct, 0) // sct_version v1(0)
	sct = append(sct, logID[:]...)
	sct = append(sct, make([]byte, 8)...) // timestamp
	sct = append(sct, 0, 0)               // no extensions
	sct = append(sct, 4, 3)               // sha256, ecdsa
	sct = append(sct, 0, 4, 1, 2, 3, 4)   // 4-byte placeholder signature
	return sct
}

// testSCTListExtension returns a SignedCertificateTimestampList extension
// containing one fake SCT per given log ID.
func testSCTListExtension(t *testing.T, logIDs ...[32]byte) pkix.Extension {
	t.Helper()
	var list []byte
	for _, logID := range logIDs {
		sct := testSCT(logID)
		list = append(list, byte(len(sct)>>8), byte(len(sct)))
		list = append(list, sct...)
	}
	full := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
	value, err := asn1.Marshal(full)
	if err != nil {
		t.Fatalf("marshalling SCT list: %s", err)
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier(util.TimestampOID), Value: value}
}

// testLeafTemplate returns a template matching the Subscriber (Server)
// Certificate Profile from CP/CPS Section 7.1, containing SCTs from two
// distinct logs.
func testLeafTemplate(t *testing.T) *x509.Certificate {
	t.Helper()
	dvOID, _ := x509.OIDFromASN1OID(asn1.ObjectIdentifier(util.BRDomainValidatedOID))
	notBefore := time.Date(2025, time.December, 1, 0, 0, 0, 0, time.UTC)
	return &x509.Certificate{
		SerialNumber: testSerial(t, 18),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames:              []string{"example.com", "www.example.com"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(0, 0, 100).Add(-time.Second),
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Policies:              []x509.OID{dvOID},
		IssuingCertificateURL: []string{"http://e99.i.lencr.org/"},
		CRLDistributionPoints: []string{"http://e99.c.lencr.org/1.crl"},
		ExtraExtensions: []pkix.Extension{
			testSCTListExtension(t, [32]byte{1}, [32]byte{2}),
		},
	}
}

// synthesizeExt returns a default version of the extension with the given OID.
// It does so by creating a throwaway cert from the given template, getting
// crypto/x509 to produce the extension for us, and then extracts the bits we
// want from the resulting cert. This is useful for creating extensions that Go
// produces from typed fields, like x509.Certificate.CRLDistributionPoints
// making the CRLDP extension.
func synthesizeExt(t *testing.T, tmpl *x509.Certificate, oid asn1.ObjectIdentifier) pkix.Extension {
	t.Helper()
	key := testKey(t, elliptic.P256())
	der, err := x509.CreateCertificate(rand.Reader, tmpl, testRootTemplate(t, key.Public()), key.Public(), key)
	if err != nil {
		t.Fatalf("creating throwaway certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing throwaway certificate: %s", err)
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return ext
		}
	}
	t.Fatalf("template did not produce extension %s", oid)
	return pkix.Extension{}
}

// criticalizeExt marks the template's extension with the given OID as critical.
// If the extension is already present in ExtraExtensions, its Critical bit is
// set directly. Otherwise, the extension value CreateCertificate would
// produce is harvested and re-added as a critical ExtraExtension, which
// overrides the non-critical extension CreateCertificate would otherwise
// generate.
func criticalizeExt(t *testing.T, tmpl *x509.Certificate, oid asn1.ObjectIdentifier) {
	t.Helper()
	for i := range tmpl.ExtraExtensions {
		if tmpl.ExtraExtensions[i].Id.Equal(oid) {
			tmpl.ExtraExtensions[i].Critical = true
			return
		}
	}
	ext := synthesizeExt(t, tmpl, oid)
	ext.Critical = true
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
}

// duplicateExt causes the template to produce two identical copies of
// the extension with the given OID.
func duplicateExt(t *testing.T, tmpl *x509.Certificate, oid asn1.ObjectIdentifier) {
	t.Helper()
	for i := range tmpl.ExtraExtensions {
		if tmpl.ExtraExtensions[i].Id.Equal(oid) {
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, tmpl.ExtraExtensions[i])
			return
		}
	}
	ext := synthesizeExt(t, tmpl, oid)
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext, ext)
}

// testPEM returns the PEM encoding of the given certificate DER.
func testPEM(t *testing.T, der []byte) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestSubscriberProfileIssuerCorrespondence(t *testing.T) {
	t.Parallel()

	intKey := testKey(t, elliptic.P384())
	intTmpl := testIntermediateTemplate(t, intKey.Public())
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, intTmpl, intKey.Public(), intKey)
	if err != nil {
		t.Fatalf("creating test issuer: %s", err)
	}

	otherKey := testKey(t, elliptic.P384())
	otherTmpl := testIntermediateTemplate(t, otherKey.Public())
	otherTmpl.Subject.CommonName = "E98"
	otherDER, err := x509.CreateCertificate(rand.Reader, otherTmpl, otherTmpl, otherKey.Public(), otherKey)
	if err != nil {
		t.Fatalf("creating test issuer: %s", err)
	}

	leafKey := testKey(t, elliptic.P256())
	leafDER, err := x509.CreateCertificate(rand.Reader, testLeafTemplate(t), intTmpl, leafKey.Public(), intKey)
	if err != nil {
		t.Fatalf("creating test certificate: %s", err)
	}
	leaf := testParseZCert(t, leafDER)

	testCases := []struct {
		name       string
		issuerPEM  string
		want       lint.LintStatus
		wantSubStr string
	}{
		{
			name:       "unconfigured",
			issuerPEM:  "",
			want:       lint.Fatal,
			wantSubStr: "lint has not been configured with the Issuing CA's certificate",
		},
		{
			name:      "matching_issuer",
			issuerPEM: testPEM(t, intDER),
			want:      lint.Pass,
		},
		{
			name:       "mismatched_issuer",
			issuerPEM:  testPEM(t, otherDER),
			want:       lint.Error,
			wantSubStr: "issuer is not byte-for-byte identical to the subject of the configured Issuing CA",
		},
		{
			name:       "garbage_config",
			issuerPEM:  "not a pem block",
			want:       lint.Fatal,
			wantSubStr: "failed to decode configured PEM certificate",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l := &subscriberServerCertificateMatchesCPSProfile{Config: &SharedConfig{IssuerCertificatePEM: tc.issuerPEM}}
			res := l.Execute(leaf)
			if res.Status != tc.want {
				t.Errorf("got status %s (%q), want %s", res.Status, res.Details, tc.want)
			}
			if !strings.Contains(res.Details, tc.wantSubStr) {
				t.Errorf("got details %q, want substring %q", res.Details, tc.wantSubStr)
			}
		})
	}
}

func TestSubscriberProfileConfigurationViaTOML(t *testing.T) {
	t.Parallel()

	intKey := testKey(t, elliptic.P384())
	intTmpl := testIntermediateTemplate(t, intKey.Public())
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, intTmpl, intKey.Public(), intKey)
	if err != nil {
		t.Fatalf("creating test issuer: %s", err)
	}

	leafKey := testKey(t, elliptic.P256())
	leafDER, err := x509.CreateCertificate(rand.Reader, testLeafTemplate(t), intTmpl, leafKey.Public(), intKey)
	if err != nil {
		t.Fatalf("creating test certificate: %s", err)
	}
	leaf := testParseZCert(t, leafDER)

	toml := fmt.Sprintf("[Global]\nissuer_certificate = '''\n%s'''\n", testPEM(t, intDER))
	cfg, err := lint.NewConfigFromString(toml)
	if err != nil {
		t.Fatalf("parsing TOML config: %s", err)
	}

	l := NewSubscriberServerCertificateMatchesCPSProfile()
	err = cfg.MaybeConfigure(l, "e_subscriber_server_certificate_matches_cps_profile")
	if err != nil {
		t.Fatalf("configuring lint: %s", err)
	}

	configured := l.(*subscriberServerCertificateMatchesCPSProfile)
	if configured.Config.issuerPEM() == "" {
		t.Fatal("TOML configuration did not populate the shared config")
	}

	res := l.Execute(leaf)
	if res.Status != lint.Pass {
		t.Errorf("got status %s (%q), want pass", res.Status, res.Details)
	}
}

func TestCrossCertifiedProfileExistingCertCorrespondence(t *testing.T) {
	t.Parallel()

	// The issuing root and the existing root being cross-signed.
	rootKey := testKey(t, elliptic.P384())
	rootTmpl := testRootTemplate(t, rootKey.Public())
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("creating test issuer: %s", err)
	}

	existingKey := testKey(t, elliptic.P384())
	existingTmpl := testRootTemplate(t, existingKey.Public())
	existingTmpl.Subject.CommonName = "ISRG Root X100"
	existingDER, err := x509.CreateCertificate(rand.Reader, existingTmpl, existingTmpl, existingKey.Public(), existingKey)
	if err != nil {
		t.Fatalf("creating existing CA certificate: %s", err)
	}

	testCases := []struct {
		name       string
		mod        func(t *testing.T, tmpl *x509.Certificate)
		want       lint.LintStatus
		wantSubStr string
	}{
		{
			name: "good",
			want: lint.Pass,
		},
		{
			name: "wrong_subject",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.Subject.CommonName = "ISRG Root X101"
			},
			want:       lint.Error,
			wantSubStr: "subject is not byte-for-byte identical to the subject of the configured existing CA Certificate",
		},
		{
			name: "wrong_skid",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.SubjectKeyId = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
			},
			want:       lint.Error,
			wantSubStr: "subjectKeyIdentifier is not byte-for-byte identical to that of the configured existing CA Certificate",
		},
		{
			name: "wrong_pathlen",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				// The existing root has no pathLenConstraint, so including one
				// in the cross-certificate is a mismatch.
				tmpl.MaxPathLen = 0
				tmpl.MaxPathLenZero = true
			},
			want:       lint.Error,
			wantSubStr: "basicConstraints pathLenConstraint is not identical to that of the configured existing CA Certificate",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tmpl := testCrossCertTemplate(t, existingKey.Public())
			tmpl.Subject = existingTmpl.Subject
			if tc.mod != nil {
				tc.mod(t, tmpl)
			}

			der, err := x509.CreateCertificate(rand.Reader, tmpl, rootTmpl, existingKey.Public(), rootKey)
			if err != nil {
				t.Fatalf("creating test certificate: %s", err)
			}
			cert := testParseZCert(t, der)

			l := &crossCertifiedSubordinateCACertificateMatchesCPSProfile{Config: &SharedConfig{
				IssuerCertificatePEM:   testPEM(t, rootDER),
				ExistingCertificatePEM: testPEM(t, existingDER),
			}}
			if !l.CheckApplies(cert) {
				t.Fatal("lint does not apply to test certificate")
			}

			res := l.Execute(cert)
			if res.Status != tc.want {
				t.Errorf("got status %s (%q), want %s", res.Status, res.Details, tc.want)
			}
			if !strings.Contains(res.Details, tc.wantSubStr) {
				t.Errorf("got details %q, want substring %q", res.Details, tc.wantSubStr)
			}
		})
	}
}

// testSelfSignedZCert builds a self-signed certificate from the root template
// using the given key and signature algorithm (zero for the default choice),
// and parses it with zcrypto.
func testSelfSignedZCert(t *testing.T, key crypto.Signer, sigAlg x509.SignatureAlgorithm) *zx509.Certificate {
	t.Helper()
	tmpl := testRootTemplate(t, key.Public())
	tmpl.SignatureAlgorithm = sigAlg
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("creating test certificate: %s", err)
	}
	return testParseZCert(t, der)
}

func TestErrResult(t *testing.T) {
	t.Parallel()

	res := errResult("some details")
	if res.Status != lint.Error {
		t.Errorf("got status %s, want %s", res.Status, lint.Error)
	}
	if res.Details != "some details" {
		t.Errorf("got details %q, want %q", res.Details, "some details")
	}
}

func TestFatalResult(t *testing.T) {
	t.Parallel()

	res := fatalResult("some details")
	if res.Status != lint.Fatal {
		t.Errorf("got status %s, want %s", res.Status, lint.Fatal)
	}
	if res.Details != "some details" {
		t.Errorf("got details %q, want %q", res.Details, "some details")
	}
}

func TestGetOuterSignatureAlgorithm(t *testing.T) {
	t.Parallel()

	cert := testSelfSignedZCert(t, testKey(t, elliptic.P384()), 0)
	got, err := getOuterSignatureAlgorithm(cert.Raw)
	if err != nil {
		t.Fatalf("getOuterSignatureAlgorithm: %s", err)
	}
	// A P-384 key signs with ecdsa-with-SHA384 by default.
	want := "300a06082a8648ce3d040303"
	if hex.EncodeToString(got) != want {
		t.Errorf("got %s, want %s", hex.EncodeToString(got), want)
	}

	_, err = getOuterSignatureAlgorithm([]byte{})
	if err == nil || !strings.Contains(err.Error(), "failed to parse certificate") {
		t.Errorf("got %v, want failure to parse certificate", err)
	}

	// A SEQUENCE whose first element is an INTEGER, not a tbsCertificate.
	_, err = getOuterSignatureAlgorithm([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	if err == nil || !strings.Contains(err.Error(), "failed to parse tbsCertificate") {
		t.Errorf("got %v, want failure to parse tbsCertificate", err)
	}

	// A SEQUENCE containing only a tbsCertificate, with no signatureAlgorithm.
	_, err = getOuterSignatureAlgorithm([]byte{0x30, 0x02, 0x30, 0x00})
	if err == nil || !strings.Contains(err.Error(), "failed to parse signatureAlgorithm") {
		t.Errorf("got %v, want failure to parse signatureAlgorithm", err)
	}
}

func TestGetExtension(t *testing.T) {
	t.Parallel()

	cert := &zx509.Certificate{
		Extensions: []zpkix.Extension{
			{Id: util.KeyUsageOID, Critical: true, Value: []byte{0x01}},
			{Id: util.BasicConstOID, Critical: false, Value: []byte{0x02}},
		},
	}

	got := getExtension(cert, util.KeyUsageOID)
	if got == nil {
		t.Fatal("got nil, want keyUsage extension")
	}
	if !got.Id.Equal(util.KeyUsageOID) || !got.Critical || !bytes.Equal(got.Value, []byte{0x01}) {
		t.Errorf("got %+v, want the keyUsage extension with its criticality and value preserved", got)
	}

	if getExtension(cert, util.SubjectAlternateNameOID) != nil {
		t.Error("got an extension for an absent OID, want nil")
	}
}

func TestParseConfiguredCertificate(t *testing.T) {
	t.Parallel()

	cert, err := parseConfiguredCertificate("")
	if err != nil {
		t.Errorf("got error %q for empty configuration, want nil", err)
	}
	if cert != nil {
		t.Error("got a certificate for empty configuration, want nil")
	}

	_, err = parseConfiguredCertificate("not a pem block")
	if err == nil || !strings.Contains(err.Error(), "failed to decode configured PEM certificate") {
		t.Errorf("got %v, want failure to decode PEM", err)
	}

	realCert := testSelfSignedZCert(t, testKey(t, elliptic.P384()), 0)

	wrongType := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: realCert.Raw}))
	_, err = parseConfiguredCertificate(wrongType)
	if err == nil || !strings.Contains(err.Error(), "failed to decode configured PEM certificate") {
		t.Errorf("got %v, want failure to decode PEM", err)
	}

	garbageDER := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}))
	_, err = parseConfiguredCertificate(garbageDER)
	if err == nil || !strings.Contains(err.Error(), "failed to parse configured certificate") {
		t.Errorf("got %v, want failure to parse certificate", err)
	}

	cert, err = parseConfiguredCertificate(testPEM(t, realCert.Raw))
	if err != nil {
		t.Fatalf("parseConfiguredCertificate: %s", err)
	}
	if cert == nil || !bytes.Equal(cert.Raw, realCert.Raw) {
		t.Error("parsed certificate does not match the configured certificate")
	}
}
