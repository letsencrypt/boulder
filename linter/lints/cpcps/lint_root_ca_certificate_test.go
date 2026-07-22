package cpcps

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/zmap/zlint/v3/lint"
)

func TestRootCACertificateMatchesCPSProfile(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		curve      elliptic.Curve
		mod        func(t *testing.T, tmpl *x509.Certificate)
		want       lint.LintStatus
		wantSubStr string
	}{
		{
			name: "good",
			want: lint.Pass,
		},
		{
			name: "good_notafter_before_2050",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.NotBefore = time.Date(2039, time.June, 1, 0, 0, 0, 0, time.UTC)
				tmpl.NotAfter = time.Date(2049, time.June, 1, 0, 0, 0, 0, time.UTC)
			},
			want: lint.Pass,
		},
		{
			name: "serial_too_short",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.SerialNumber = big.NewInt(12345)
			},
			want:       lint.Error,
			wantSubStr: "serialNumber is not approximately 128 bits",
		},
		{
			name: "validity_too_long",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.NotAfter = tmpl.NotAfter.Add(24 * time.Hour)
			},
			want:       lint.Error,
			wantSubStr: "validity is more than 3660 days",
		},
		{
			name: "wrong_organization",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.Subject.Organization = []string{"Internet Security Research Group"}
			},
			want:       lint.Error,
			wantSubStr: "subject organizationName is not ISRG",
		},
		{
			name: "missing_country",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.Subject.Country = nil
			},
			want:       lint.Error,
			wantSubStr: "subject does not contain exactly C, O, and CN attributes",
		},
		{
			name: "missing_common_name",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.Subject.CommonName = ""
			},
			want:       lint.Error,
			wantSubStr: "subject does not contain exactly C, O, and CN attributes",
		},
		{
			name: "extra_subject_attribute",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.Subject.OrganizationalUnit = []string{"Roots"}
			},
			want:       lint.Error,
			wantSubStr: "subject does not contain exactly C, O, and CN attributes",
		},
		{
			name:       "wrong_curve",
			curve:      elliptic.P256(),
			want:       lint.Error,
			wantSubStr: "ECDSA curve P-256 is not allowed",
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
			name: "missing_crl_sign",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.KeyUsage = x509.KeyUsageCertSign
			},
			want:       lint.Error,
			wantSubStr: "keyUsage does not assert exactly the bits required by the profile",
		},
		{
			name: "wrong_skid",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.SubjectKeyId = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
			},
			want:       lint.Error,
			wantSubStr: "subjectKeyIdentifier is not the RFC 7093",
		},
		{
			name: "extra_extension",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.ExtraExtensions = []pkix.Extension{
					{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44947, 999}, Value: []byte{0x05, 0x00}},
				}
			},
			want:       lint.Error,
			wantSubStr: "unexpected extension",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			curve := tc.curve
			if curve == nil {
				curve = elliptic.P384()
			}
			key := testKey(t, curve)

			tmpl := testRootTemplate(t, key.Public())
			if tc.mod != nil {
				tc.mod(t, tmpl)
			}

			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
			if err != nil {
				t.Fatalf("creating test certificate: %s", err)
			}
			cert := testParseZCert(t, der)

			l := NewRootCACertificateMatchesCPSProfile()
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

func TestRootCACertificateMatchesCPSProfileCheckApplies(t *testing.T) {
	t.Parallel()

	rootKey := testKey(t, elliptic.P384())
	rootTmpl := testRootTemplate(t, rootKey.Public())

	intKey := testKey(t, elliptic.P384())
	intTmpl := testIntermediateTemplate(t, intKey.Public())

	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, rootTmpl, intKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("creating test certificate: %s", err)
	}

	l := NewRootCACertificateMatchesCPSProfile()
	if l.CheckApplies(testParseZCert(t, intDER)) {
		t.Error("lint applies to non-self-signed intermediate certificate")
	}
}
