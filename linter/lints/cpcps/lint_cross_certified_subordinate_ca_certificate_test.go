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
// conferring a second issuance path upon an existing CA Certificate, shaped
// by default like an ISRG root.
func testCrossCertTemplate(t *testing.T, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	notBefore := time.Date(2025, time.November, 1, 0, 0, 0, 0, time.UTC)
	return &x509.Certificate{
		SerialNumber: testSerial(t, 16),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"ISRG"},
			CommonName:   "Root X",
		},
		PublicKey: pub,
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

	// This is the issuer of the existing cert which we're cross-signing.
	existingIssuerKey := testKey(t, elliptic.P384())
	existingIssuerTmpl := testRootTemplate(t, existingIssuerKey.Public())
	_, err := x509.CreateCertificate(rand.Reader, existingIssuerTmpl, existingIssuerTmpl, existingIssuerKey.Public(), existingIssuerKey)
	if err != nil {
		t.Fatalf("creating test issuer: %s", err)
	}

	// This is the CA which is doing the cross-signing.
	issuerKey := testKey(t, elliptic.P384())
	issuerTmpl := testRootTemplate(t, issuerKey.Public())
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, issuerKey.Public(), issuerKey)
	if err != nil {
		t.Fatalf("creating test issuer: %s", err)
	}

	// A real RSA key to exercise Section 6.1.6's RSA requirements, since most
	// test cases use ECDSA for speed.
	rsa2048Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA test key: %s", err)
	}

	testCases := []struct {
		name       string
		pub        crypto.PublicKey
		mod        func(t *testing.T, tmpl, existing *x509.Certificate)
		want       lint.LintStatus
		wantSubStr string
	}{
		{
			name: "good_root",
			want: lint.Pass,
		},
		{
			name: "good_intermediate",
			pub:  rsa2048Key.Public(),
			mod: func(t *testing.T, tmpl, existing *x509.Certificate) {
				for _, cert := range []*x509.Certificate{tmpl, existing} {
					cert.Subject = pkix.Name{
						Country:      []string{"US"},
						Organization: []string{"Let's Encrypt"},
						CommonName:   "E100",
					}
					cert.MaxPathLen = 0
					cert.MaxPathLenZero = true
				}
			},
			want: lint.Pass,
		},
		{
			name: "spki_mismatch",
			mod: func(t *testing.T, tmpl, existing *x509.Certificate) {
				existing.PublicKey = testKey(t, elliptic.P384()).Public()
			},
			want:       lint.Error,
			wantSubStr: "subjectPublicKeyInfo is not byte-for-byte identical to that of the configured existing CA Certificate",
		},
		{
			name: "good_minimal_serial",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				// Exactly 101 bits, the smallest permitted length.
				tmpl.SerialNumber = new(big.Int).Lsh(big.NewInt(1), 100)
			},
			want: lint.Pass,
		},
		{
			name: "serial_too_short",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				// Exactly 100 bits, one bit short of the required minimum.
				tmpl.SerialNumber = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 100), big.NewInt(1))
			},
			want:       lint.Error,
			wantSubStr: "serialNumber is not more than 100 bits long",
		},
		{
			name: "pathlen_mismatch",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
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
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				// One second past the maximum 1098-day validity period.
				tmpl.NotAfter = tmpl.NotBefore.AddDate(0, 0, 1098)
			},
			want:       lint.Error,
			wantSubStr: "validity is more than 1098 days",
		},
		{
			name: "validity_negative",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				tmpl.NotAfter = tmpl.NotBefore.Add(-time.Second)
			},
			want:       lint.Error,
			wantSubStr: "validity is negative",
		},
		{
			name: "extra_key_usage_bit",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				tmpl.KeyUsage |= x509.KeyUsageDigitalSignature
			},
			want:       lint.Error,
			wantSubStr: "keyUsage does not assert exactly the bits required by the profile",
		},
		{
			name: "missing_country",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				tmpl.Subject.Country = nil
			},
			want:       lint.Error,
			wantSubStr: "subject is not byte-for-byte identical to the subject of the configured existing CA Certificate",
		},
		{
			name: "extra_eku",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
			},
			want:       lint.Error,
			wantSubStr: "extKeyUsage does not contain exactly id-kp-serverAuth",
		},
		{
			name: "missing_aia",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				tmpl.IssuingCertificateURL = nil
			},
			want:       lint.Error,
			wantSubStr: "authorityInformationAccess extension is not present",
		},
		{
			name: "https_aia",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				tmpl.IssuingCertificateURL = []string{"https://x99.i.lencr.org/"}
			},
			want:       lint.Error,
			wantSubStr: "authorityInformationAccess caIssuers URI is not an http URL",
		},
		{
			name: "aia_unparsable",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				tmpl.IssuingCertificateURL = []string{"http://x99.i.lencr.org/%zz"}
			},
			want:       lint.Error,
			wantSubStr: "authorityInformationAccess caIssuers URI is not an http URL",
		},
		{
			name: "aia_no_hostname",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				tmpl.IssuingCertificateURL = []string{"http:///x99.crt"}
			},
			want:       lint.Error,
			wantSubStr: "authorityInformationAccess caIssuers URI hostname is not a domain under a public suffix",
		},
		{
			name: "aia_bad_tld",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				tmpl.IssuingCertificateURL = []string{"http://x99.i.lencr.invalid/"}
			},
			want:       lint.Error,
			wantSubStr: "authorityInformationAccess caIssuers URI hostname is not a domain under a public suffix",
		},
		{
			name: "https_crldp",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				tmpl.CRLDistributionPoints = []string{"https://x99.c.lencr.org/1.crl"}
			},
			want:       lint.Error,
			wantSubStr: "crlDistributionPoints URI is not an http URL",
		},
		{
			name: "crldp_unparsable",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				tmpl.CRLDistributionPoints = []string{"http://x99.c.lencr.org/%zz"}
			},
			want:       lint.Error,
			wantSubStr: "crlDistributionPoints URI is not an http URL",
		},
		{
			name: "crldp_no_hostname",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				tmpl.CRLDistributionPoints = []string{"http:///1.crl"}
			},
			want:       lint.Error,
			wantSubStr: "crlDistributionPoints URI hostname is not a domain under a public suffix",
		},
		{
			name: "crldp_bad_tld",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
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
			// Only the Root CA (4096) and Subordinate CA (2048) RSA sizes
			// from Section 6.1.5 are allowed; the Subscriber-only 3072 size
			// is not.
			name:       "rsa_modulus_size_3072",
			pub:        &rsa.PublicKey{N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 3071), big.NewInt(1)), E: 65537},
			want:       lint.Error,
			wantSubStr: "RSA encoded modulus size 3072 is not allowed",
		},
		{
			name: "critical_aia",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				criticalizeExt(t, tmpl, asn1.ObjectIdentifier(authorityInformationAccessOID))
			},
			want:       lint.Error,
			wantSubStr: "authorityInformationAccess extension is critical",
		},
		{
			name: "critical_certificate_policies",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				criticalizeExt(t, tmpl, asn1.ObjectIdentifier(certificatePoliciesOID))
			},
			want:       lint.Error,
			wantSubStr: "certificatePolicies extension is critical",
		},
		{
			name: "critical_crldp",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				criticalizeExt(t, tmpl, asn1.ObjectIdentifier(crlDistributionPointsOID))
			},
			want:       lint.Error,
			wantSubStr: "crlDistributionPoints extension is critical",
		},
		{
			name: "critical_eku",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				criticalizeExt(t, tmpl, asn1.ObjectIdentifier(extKeyUsageOID))
			},
			want:       lint.Error,
			wantSubStr: "extKeyUsage extension is critical",
		},
		{
			name: "duplicate_extension",
			mod: func(t *testing.T, tmpl, _ *x509.Certificate) {
				duplicateExt(t, tmpl, asn1.ObjectIdentifier(keyUsageOID))
			},
			want:       lint.Error,
			wantSubStr: "duplicate extension 2.5.29.15",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			subjectKey := testKey(t, elliptic.P384())

			// The existing CA Certificate being cross-signed and the
			// cross-certificate template start out identical; tc.mod may modify both.
			existingTmpl := testCrossCertTemplate(t, subjectKey.Public())
			crossTmpl := testCrossCertTemplate(t, subjectKey.Public())
			if tc.pub != nil {
				existingTmpl.PublicKey = tc.pub
				crossTmpl.PublicKey = tc.pub
			}
			if tc.mod != nil {
				tc.mod(t, crossTmpl, existingTmpl)
			}

			existingDER, err := x509.CreateCertificate(rand.Reader, existingTmpl, existingIssuerTmpl, existingTmpl.PublicKey, existingIssuerKey)
			if err != nil {
				t.Fatalf("creating existing CA certificate: %s", err)
			}

			crossDER, err := x509.CreateCertificate(rand.Reader, crossTmpl, issuerTmpl, crossTmpl.PublicKey, issuerKey)
			if err != nil {
				t.Fatalf("creating test certificate: %s", err)
			}
			cert := testParseZCert(t, crossDER)

			l := &crossCertifiedSubordinateCACertificateMatchesCPSProfile{Config: &SharedConfig{
				IssuerCertificatePEM:   testPEM(t, issuerDER),
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
