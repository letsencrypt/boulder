package cpcps

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
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
		// 1098 days, inclusive of the final second.
		NotAfter: notBefore.AddDate(0, 0, 1098).Add(-time.Second),
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
		pub        crypto.PublicKey
		mod        func(t *testing.T, tmpl *x509.Certificate)
		want       lint.LintStatus
		wantSubStr string
	}{
		{
			name: "good",
			want: lint.Pass,
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
				// One second past the maximum 1098-day validity period.
				tmpl.NotAfter = tmpl.NotBefore.AddDate(0, 0, 1098)
			},
			want:       lint.Error,
			wantSubStr: "validity is more than 1098 days",
		},
		{
			name: "validity_negative",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.NotAfter = tmpl.NotBefore.Add(-time.Second)
			},
			want:       lint.Error,
			wantSubStr: "validity is negative",
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
		{
			name: "https_aia",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.IssuingCertificateURL = []string{"https://x99.i.lencr.org/"}
			},
			want:       lint.Error,
			wantSubStr: "authorityInformationAccess caIssuers URI is not an http URL",
		},
		{
			name: "aia_unparseable",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.IssuingCertificateURL = []string{"http://x99.i.lencr.org/%zz"}
			},
			want:       lint.Error,
			wantSubStr: "authorityInformationAccess caIssuers URI is not an http URL",
		},
		{
			name: "aia_no_hostname",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.IssuingCertificateURL = []string{"http:///x99.crt"}
			},
			want:       lint.Error,
			wantSubStr: "authorityInformationAccess caIssuers URI hostname is not a domain under a public suffix",
		},
		{
			name: "aia_bad_tld",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.IssuingCertificateURL = []string{"http://x99.i.lencr.invalid/"}
			},
			want:       lint.Error,
			wantSubStr: "authorityInformationAccess caIssuers URI hostname is not a domain under a public suffix",
		},
		{
			name: "https_crldp",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.CRLDistributionPoints = []string{"https://x99.c.lencr.org/1.crl"}
			},
			want:       lint.Error,
			wantSubStr: "crlDistributionPoints URI is not an http URL",
		},
		{
			name: "crldp_unparseable",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.CRLDistributionPoints = []string{"http://x99.c.lencr.org/%zz"}
			},
			want:       lint.Error,
			wantSubStr: "crlDistributionPoints URI is not an http URL",
		},
		{
			name: "crldp_no_hostname",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.CRLDistributionPoints = []string{"http:///1.crl"}
			},
			want:       lint.Error,
			wantSubStr: "crlDistributionPoints URI hostname is not a domain under a public suffix",
		},
		{
			name: "crldp_bad_tld",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.CRLDistributionPoints = []string{"http://x99.c.lencr.invalid/1.crl"}
			},
			want:       lint.Error,
			wantSubStr: "crlDistributionPoints URI hostname is not a domain under a public suffix",
		},
		{
			// 2^4095 + 1 is a 4096-bit odd modulus, but the exponent is wrong.
			name:       "rsa_exponent_not_65537",
			pub:        &rsa.PublicKey{N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 4095), big.NewInt(1)), E: 3},
			want:       lint.Error,
			wantSubStr: "RSA public exponent 3 is not 65537",
		},
		{
			// 2^4095 is a 4096-bit modulus, but it is even.
			name:       "rsa_modulus_even",
			pub:        &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 4095), E: 65537},
			want:       lint.Error,
			wantSubStr: "RSA modulus is even",
		},
		{
			// 2^4095 + 1 is a 4096-bit odd modulus, but is divisible by 3.
			name:       "rsa_modulus_small_factor",
			pub:        &rsa.PublicKey{N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 4095), big.NewInt(1)), E: 65537},
			want:       lint.Error,
			wantSubStr: "RSA modulus has a prime factor smaller than 752",
		},
		{
			// 2^4094 has a bit length of 4095, but still encodes in 512
			// octets, so its encoded modulus size is 4096 bits: it passes the
			// size check and fails the parity check instead.
			name:       "rsa_modulus_leading_zero_bit",
			pub:        &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 4094), E: 65537},
			want:       lint.Error,
			wantSubStr: "RSA modulus is even",
		},
		{
			// 2^4087 encodes in 511 octets, so its encoded modulus size is
			// 4088 bits.
			name:       "rsa_modulus_wrong_encoded_size",
			pub:        &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 4087), E: 65537},
			want:       lint.Error,
			wantSubStr: "RSA encoded modulus size 4088 is not allowed",
		},
		{
			name: "critical_aia",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				criticalizeExt(t, tmpl, asn1.ObjectIdentifier(authorityInformationAccessOID))
			},
			want:       lint.Error,
			wantSubStr: "authorityInformationAccess extension is critical",
		},
		{
			name: "critical_certificate_policies",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				criticalizeExt(t, tmpl, asn1.ObjectIdentifier(certificatePoliciesOID))
			},
			want:       lint.Error,
			wantSubStr: "certificatePolicies extension is critical",
		},
		{
			name: "critical_crldp",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				criticalizeExt(t, tmpl, asn1.ObjectIdentifier(crlDistributionPointsOID))
			},
			want:       lint.Error,
			wantSubStr: "crlDistributionPoints extension is critical",
		},
		{
			name: "critical_eku",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				criticalizeExt(t, tmpl, asn1.ObjectIdentifier(extKeyUsageOID))
			},
			want:       lint.Error,
			wantSubStr: "extKeyUsage extension is critical",
		},
		{
			name: "duplicate_extension",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				duplicateExt(t, tmpl, asn1.ObjectIdentifier(keyUsageOID))
			},
			want:       lint.Error,
			wantSubStr: "duplicate extension 2.5.29.15",
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

			pub := crypto.PublicKey(crossKey.Public())
			if tc.pub != nil {
				pub = tc.pub
			}

			tmpl := testCrossCertTemplate(t, pub)
			if tc.mod != nil {
				tc.mod(t, tmpl)
			}

			der, err := x509.CreateCertificate(rand.Reader, tmpl, rootTmpl, pub, rootKey)
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
