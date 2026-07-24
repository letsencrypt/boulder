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

func TestTLSSubordinateCACertificateMatchesCPSProfile(t *testing.T) {
	t.Parallel()

	rootKey := testKey(t, elliptic.P384())
	rootTmpl := testRootTemplate(t, rootKey.Public())
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("creating test issuer: %s", err)
	}

	testCases := []struct {
		name       string
		curve      elliptic.Curve
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
			name: "wrong_organization",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.Subject.Organization = []string{"LE Incorporated"}
			},
			want:       lint.Error,
			wantSubStr: "subject organizationName is not Let's Encrypt",
		},
		{
			name: "extra_subject_attribute",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.Subject.OrganizationalUnit = []string{"Intermediates"}
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
			name:       "wrong_curve",
			curve:      elliptic.P521(),
			want:       lint.Error,
			wantSubStr: "ECDSA curve P-521 is not allowed",
		},
		{
			name: "missing_pathlen",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.MaxPathLen = -1
				tmpl.MaxPathLenZero = false
			},
			want:       lint.Error,
			wantSubStr: "basicConstraints pathLenConstraint is not 0",
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
			name: "missing_digital_signature",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
			},
			want:       lint.Error,
			wantSubStr: "keyUsage does not assert exactly the bits required by the profile",
		},
		{
			name: "wrong_policy",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				ovOID, err := x509.OIDFromInts([]uint64{2, 23, 140, 1, 2, 2})
				if err != nil {
					t.Fatalf("creating OID: %s", err)
				}
				tmpl.Policies = []x509.OID{ovOID}
			},
			want:       lint.Error,
			wantSubStr: "certificatePolicies does not contain exactly the Domain Validated Reserved Policy Identifier",
		},
		{
			name: "missing_crldp",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.CRLDistributionPoints = nil
			},
			want:       lint.Error,
			wantSubStr: "crlDistributionPoints extension is not present",
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
			// 2^2047 + 1 is a 2048-bit odd modulus, but the exponent is wrong.
			name:       "rsa_exponent_not_65537",
			pub:        &rsa.PublicKey{N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 2047), big.NewInt(1)), E: 3},
			want:       lint.Error,
			wantSubStr: "RSA public exponent 3 is not 65537",
		},
		{
			// 2^2047 is a 2048-bit modulus, but it is even.
			name:       "rsa_modulus_even",
			pub:        &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537},
			want:       lint.Error,
			wantSubStr: "RSA modulus is even",
		},
		{
			// 2^2047 + 1 is a 2048-bit odd modulus, but is divisible by 3.
			name:       "rsa_modulus_small_factor",
			pub:        &rsa.PublicKey{N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 2047), big.NewInt(1)), E: 65537},
			want:       lint.Error,
			wantSubStr: "RSA modulus has a prime factor smaller than 752",
		},
		{
			name: "aia_contains_ocsp",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.OCSPServer = []string{"http://ocsp.x99.lencr.org/"}
			},
			want:       lint.Error,
			wantSubStr: "authorityInformationAccess contains an OCSP entry",
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
			pub := crypto.PublicKey(testKey(t, curve).Public())
			if tc.pub != nil {
				pub = tc.pub
			}

			tmpl := testIntermediateTemplate(t, pub)
			if tc.mod != nil {
				tc.mod(t, tmpl)
			}

			der, err := x509.CreateCertificate(rand.Reader, tmpl, rootTmpl, pub, rootKey)
			if err != nil {
				t.Fatalf("creating test certificate: %s", err)
			}
			cert := testParseZCert(t, der)

			l := &tlsSubordinateCACertificateMatchesCPSProfile{Config: &SharedConfig{IssuerCertificatePEM: testPEM(t, rootDER)}}
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

func TestTLSSubordinateCACertificateMatchesCPSProfileCheckApplies(t *testing.T) {
	t.Parallel()

	rootKey := testKey(t, elliptic.P384())
	rootTmpl := testRootTemplate(t, rootKey.Public())

	l := NewTLSSubordinateCACertificateMatchesCPSProfile()

	// A cross-certified subordinate CA certificate (subject O=ISRG) is covered
	// by the cross-certified profile, not this one.
	crossKey := testKey(t, elliptic.P384())
	crossTmpl := testIntermediateTemplate(t, crossKey.Public())
	crossTmpl.Subject.Organization = []string{"ISRG"}
	crossDER, err := x509.CreateCertificate(rand.Reader, crossTmpl, rootTmpl, crossKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("creating test certificate: %s", err)
	}
	if l.CheckApplies(testParseZCert(t, crossDER)) {
		t.Error("lint applies to cross-certified (subject O=ISRG) certificate")
	}

	// A self-signed root is covered by the root profile, not this one.
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("creating test certificate: %s", err)
	}
	if l.CheckApplies(testParseZCert(t, rootDER)) {
		t.Error("lint applies to self-signed root certificate")
	}
}
