package cpcps

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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
			name: "serial_too_long",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.SerialNumber = testSerial(t, 18)
			},
			want:       lint.Error,
			wantSubStr: "serialNumber is not approximately 128 bits",
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
			wantSubStr: "authorityInformationAccess caIssuers URI does not use the http scheme",
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
			intKey := testKey(t, curve)

			tmpl := testIntermediateTemplate(t, intKey.Public())
			if tc.mod != nil {
				tc.mod(t, tmpl)
			}

			der, err := x509.CreateCertificate(rand.Reader, tmpl, rootTmpl, intKey.Public(), rootKey)
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
