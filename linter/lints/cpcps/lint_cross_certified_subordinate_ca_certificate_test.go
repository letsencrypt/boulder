package cpcps

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"github.com/zmap/zlint/v3/lint"
)

// testCrossCertTemplate returns a template matching the Cross-Certified
// Subordinate CA Certificate Profile from CP/CPS Section 7.1: a certificate
// conferring a second issuance path upon an existing ISRG root.
func testCrossCertTemplate(t *testing.T, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	notBefore := time.Date(2025, time.November, 1, 0, 0, 0, 0, time.UTC)
	return &x509.Certificate{
		SerialNumber: testSerial(t, 16),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"ISRG"},
			CommonName:   "ISRG Root X100",
		},
		NotBefore: notBefore,
		NotAfter:  notBefore.AddDate(5, 0, 0).Add(-time.Second),
		// The existing CA Certificate being cross-signed is a root, which has
		// no pathLenConstraint, so MaxPathLen and MaxPathLenZero are left at
		// their zero values.
		BasicConstraintsValid: true,
		IsCA:                  true,
		// Cross-certificates assert only the keyCertSign and cRLSign bits.
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Policies:              []x509.OID{testDomainValidatedOID},
		IssuingCertificateURL: []string{"http://x99.i.lencr.org/"},
		CRLDistributionPoints: []string{"http://x99.c.lencr.org/1.crl"},
		SubjectKeyId:          testRFC7093SKID(t, pub),
	}
}

func TestCrossCertifiedSubordinateCACertificateMatchesCPSProfile(t *testing.T) {
	t.Parallel()

	rootKey := testKey(t, elliptic.P384())
	rootTmpl := testRootTemplate(t, rootKey.Public())
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("creating test issuer: %s", err)
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
			name: "pathlen_mismatch",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				// The existing CA Certificate has no pathLenConstraint, so
				// including one in the cross-certificate is a mismatch.
				tmpl.MaxPathLen = 0
				tmpl.MaxPathLenZero = true
			},
			want:       lint.Error,
			wantSubStr: "basicConstraints pathLenConstraint is not identical to that of the configured existing CA Certificate",
		},
		{
			name: "validity_too_long",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.NotAfter = tmpl.NotBefore.AddDate(9, 0, 0)
			},
			want:       lint.Error,
			wantSubStr: "validity is more than 8 years",
		},
		{
			name: "extra_key_usage_bit",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.KeyUsage |= x509.KeyUsageDigitalSignature
			},
			want:       lint.Error,
			wantSubStr: "keyUsage does not assert exactly the bits required by the profile",
		},
		{
			name: "missing_country",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.Subject.Country = nil
			},
			want:       lint.Error,
			wantSubStr: "subject is not byte-for-byte identical to the subject of the configured existing CA Certificate",
		},
		{
			name: "extra_eku",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
			},
			want:       lint.Error,
			wantSubStr: "extKeyUsage does not contain exactly id-kp-serverAuth",
		},
		{
			name: "missing_aia",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.IssuingCertificateURL = nil
			},
			want:       lint.Error,
			wantSubStr: "authorityInformationAccess extension is not present",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// The existing CA Certificate being cross-signed: self-signed by
			// the same key, with the same subject, SKID, and (absent)
			// pathLenConstraint as the unmodified cross-certificate template.
			crossKey := testKey(t, elliptic.P384())
			existingDER, err := x509.CreateCertificate(rand.Reader, testCrossCertTemplate(t, crossKey.Public()), testCrossCertTemplate(t, crossKey.Public()), crossKey.Public(), crossKey)
			if err != nil {
				t.Fatalf("creating existing CA certificate: %s", err)
			}

			tmpl := testCrossCertTemplate(t, crossKey.Public())
			if tc.mod != nil {
				tc.mod(t, tmpl)
			}

			der, err := x509.CreateCertificate(rand.Reader, tmpl, rootTmpl, crossKey.Public(), rootKey)
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

func TestCrossCertifiedSubordinateCACertificateMatchesCPSProfileCheckApplies(t *testing.T) {
	t.Parallel()

	rootKey := testKey(t, elliptic.P384())
	rootTmpl := testRootTemplate(t, rootKey.Public())

	// A TLS subordinate CA certificate (subject O=Let's Encrypt) is covered by
	// the TLS subordinate profile, not this one.
	intKey := testKey(t, elliptic.P384())
	intTmpl := testIntermediateTemplate(t, intKey.Public())

	der, err := x509.CreateCertificate(rand.Reader, intTmpl, rootTmpl, intKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("creating test certificate: %s", err)
	}

	l := NewCrossCertifiedSubordinateCACertificateMatchesCPSProfile()
	if l.CheckApplies(testParseZCert(t, der)) {
		t.Error("lint applies to TLS subordinate CA certificate")
	}
}
