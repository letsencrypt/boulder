package cpcps

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/zmap/zlint/v3/lint"
)

func TestSubscriberServerCertificateMatchesCPSProfile(t *testing.T) {
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
			name: "good_cn_omitted",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.Subject = pkix.Name{}
			},
			want: lint.Pass,
		},
		{
			name: "good_ip_cn",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.Subject.CommonName = "10.1.2.3"
				tmpl.DNSNames = nil
				tmpl.IPAddresses = []net.IP{net.ParseIP("10.1.2.3")}
			},
			want: lint.Pass,
		},
		{
			name: "good_with_skid",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				// This mod relies on the leaf key being generated before the
				// template is modified; see the test body.
			},
			want: lint.Pass,
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
			name: "validity_negative",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.NotAfter = tmpl.NotBefore.Add(-time.Second)
			},
			want:       lint.Error,
			wantSubStr: "validity is negative",
		},
		{
			name: "serial_too_short",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.SerialNumber = testSerial(t, 16)
			},
			want:       lint.Error,
			wantSubStr: "serialNumber is not approximately 144 bits",
		},
		{
			name: "cn_not_in_sans",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.Subject.CommonName = "other.example.org"
			},
			want:       lint.Error,
			wantSubStr: "subject commonName is not one of the subjectAltName dNSName values",
		},
		{
			name: "ip_cn_not_in_sans",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.Subject.CommonName = "10.1.2.3"
			},
			want:       lint.Error,
			wantSubStr: "subject commonName is not one of the subjectAltName ipAddress values",
		},
		{
			name: "extra_subject_attribute",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.Subject.Organization = []string{"Example"}
			},
			want:       lint.Error,
			wantSubStr: "subject contains an attribute other than commonName",
		},
		{
			name: "email_san",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.EmailAddresses = []string{"admin@example.com"}
			},
			want:       lint.Error,
			wantSubStr: "subjectAltName contains a name of a type other than dNSName or ipAddress",
		},
		{
			name: "too_many_sans",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				var names []string
				for i := range 101 {
					names = append(names, fmt.Sprintf("%d.example.com", i))
				}
				tmpl.Subject = pkix.Name{}
				tmpl.DNSNames = names
			},
			want:       lint.Error,
			wantSubStr: "subjectAltName does not contain between 1 and 100 names",
		},
		{
			name: "no_sans",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.Subject = pkix.Name{}
				tmpl.DNSNames = nil
				tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
					// An empty, critical subjectAltName extension containing
					// an empty GeneralNames SEQUENCE.
					Id:       asn1.ObjectIdentifier{2, 5, 29, 17},
					Critical: true,
					Value:    []byte{0x30, 0x00},
				})
			},
			want:       lint.Error,
			wantSubStr: "subjectAltName does not contain between 1 and 100 names",
		},
		{
			name: "extra_key_usage_bit",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
			},
			want:       lint.Error,
			wantSubStr: "keyUsage asserts bits beyond digitalSignature",
		},
		{
			name: "missing_digital_signature",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.KeyUsage = x509.KeyUsageKeyEncipherment
			},
			want:       lint.Error,
			wantSubStr: "keyUsage does not assert digitalSignature",
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
			name: "missing_policies",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.Policies = nil
			},
			want:       lint.Error,
			wantSubStr: "certificatePolicies extension is not present",
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
			name: "missing_crldp",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.CRLDistributionPoints = nil
			},
			want:       lint.Error,
			wantSubStr: "crlDistributionPoints extension is not present",
		},
		{
			name: "one_sct",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.ExtraExtensions = []pkix.Extension{
					testSCTListExtension(t, [32]byte{1}),
				}
			},
			want:       lint.Error,
			wantSubStr: "signedCertificateTimestampList does not contain SCTs from at least two distinct logs",
		},
		{
			name: "two_scts_same_log",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.ExtraExtensions = []pkix.Extension{
					testSCTListExtension(t, [32]byte{1}, [32]byte{1}),
				}
			},
			want:       lint.Error,
			wantSubStr: "signedCertificateTimestampList does not contain SCTs from at least two distinct logs",
		},
		{
			name: "missing_scts",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.ExtraExtensions = nil
			},
			want:       lint.Error,
			wantSubStr: "signedCertificateTimestampList extension is not present",
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
				tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
					Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44947, 999}, Value: []byte{0x05, 0x00},
				})
			},
			want:       lint.Error,
			wantSubStr: "unexpected extension",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			leafKey := testKey(t, elliptic.P256())
			tmpl := testLeafTemplate(t)
			if tc.name == "good_with_skid" {
				tmpl.SubjectKeyId = testRFC7093SKID(t, leafKey.Public())
			}
			if tc.mod != nil {
				tc.mod(t, tmpl)
			}

			der, err := x509.CreateCertificate(rand.Reader, tmpl, intTmpl, leafKey.Public(), intKey)
			if err != nil {
				t.Fatalf("creating test certificate: %s", err)
			}
			cert := testParseZCert(t, der)

			l := &subscriberServerCertificateMatchesCPSProfile{Config: &SharedConfig{IssuerCertificatePEM: testPEM(t, intDER)}}
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

func TestSubscriberServerCertificateMatchesCPSProfileCheckApplies(t *testing.T) {
	t.Parallel()

	intKey := testKey(t, elliptic.P384())
	intTmpl := testIntermediateTemplate(t, intKey.Public())

	// A precertificate (containing the CT poison extension) is covered by the
	// precertificate profile, not this one.
	leafKey := testKey(t, elliptic.P256())
	tmpl := testLeafTemplate(t)
	tmpl.ExtraExtensions = []pkix.Extension{
		{Id: testCTPoisonOID, Critical: true, Value: []byte{0x05, 0x00}},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, intTmpl, leafKey.Public(), intKey)
	if err != nil {
		t.Fatalf("creating test certificate: %s", err)
	}

	l := NewSubscriberServerCertificateMatchesCPSProfile()
	if l.CheckApplies(testParseZCert(t, der)) {
		t.Error("lint applies to precertificate")
	}
}
