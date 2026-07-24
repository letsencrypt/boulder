package cpcps

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"

	"github.com/zmap/zlint/v3/lint"
)

// testPrecertTemplate returns a template matching the Precertificate Profile
// from CP/CPS Section 7.1: the Subscriber (Server) Certificate Profile with
// the SignedCertificateTimestampList extension replaced by a critical CT
// poison extension.
func testPrecertTemplate(t *testing.T) *x509.Certificate {
	t.Helper()
	tmpl := testLeafTemplate(t)
	tmpl.ExtraExtensions = []pkix.Extension{
		{Id: testCTPoisonOID, Critical: true, Value: []byte{0x05, 0x00}},
	}
	return tmpl
}

func TestPrecertificateMatchesCPSProfile(t *testing.T) {
	t.Parallel()

	intKey := testKey(t, elliptic.P384())
	intTmpl := testIntermediateTemplate(t, intKey.Public())
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, intTmpl, intKey.Public(), intKey)
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
			name: "poison_not_critical",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.ExtraExtensions = []pkix.Extension{
					{Id: testCTPoisonOID, Critical: false, Value: []byte{0x05, 0x00}},
				}
			},
			want:       lint.Error,
			wantSubStr: "CT poison extension is not critical",
		},
		{
			name: "scts_alongside_poison",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.ExtraExtensions = append(tmpl.ExtraExtensions,
					testSCTListExtension(t, [32]byte{1}, [32]byte{2}))
			},
			want:       lint.Error,
			wantSubStr: "unexpected extension",
		},
		{
			name: "validity_too_long",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.NotAfter = tmpl.NotBefore.AddDate(0, 0, 101)
			},
			want:       lint.Error,
			wantSubStr: "validity is more than 100 days",
		},
		{
			name: "good_minimal_serial",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				// Exactly 101 bits, the smallest permitted length.
				tmpl.SerialNumber = new(big.Int).Lsh(big.NewInt(1), 100)
			},
			want: lint.Pass,
		},
		{
			name: "serial_too_short",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				// Exactly 100 bits, one bit short of the required minimum.
				tmpl.SerialNumber = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 100), big.NewInt(1))
			},
			want:       lint.Error,
			wantSubStr: "serialNumber is not more than 100 bits long",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			leafKey := testKey(t, elliptic.P256())
			tmpl := testPrecertTemplate(t)
			if tc.mod != nil {
				tc.mod(t, tmpl)
			}

			der, err := x509.CreateCertificate(rand.Reader, tmpl, intTmpl, leafKey.Public(), intKey)
			if err != nil {
				t.Fatalf("creating test certificate: %s", err)
			}
			cert := testParseZCert(t, der)

			l := &precertificateMatchesCPSProfile{Config: &SharedConfig{IssuerCertificatePEM: testPEM(t, intDER)}}
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

func TestPrecertificateMatchesCPSProfileCheckApplies(t *testing.T) {
	t.Parallel()

	intKey := testKey(t, elliptic.P384())
	intTmpl := testIntermediateTemplate(t, intKey.Public())

	// A final certificate (without the CT poison extension) is covered by the
	// subscriber server certificate profile, not this one.
	leafKey := testKey(t, elliptic.P256())
	tmpl := testLeafTemplate(t)

	der, err := x509.CreateCertificate(rand.Reader, tmpl, intTmpl, leafKey.Public(), intKey)
	if err != nil {
		t.Fatalf("creating test certificate: %s", err)
	}

	l := NewPrecertificateMatchesCPSProfile()
	if l.CheckApplies(testParseZCert(t, der)) {
		t.Error("lint applies to final (non-poisoned) certificate")
	}
}
