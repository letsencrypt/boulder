package cpcps

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
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
			name: "cn_not_a_string",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				// A subject whose commonName value is an OCTET STRING rather
				// than any ASN.1 string type. RawSubject is used verbatim by
				// CreateCertificate, overriding the Subject field.
				rawSubject, err := asn1.Marshal(pkix.RDNSequence{
					pkix.RelativeDistinguishedNameSET{
						pkix.AttributeTypeAndValue{
							Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
							Value: []byte("example.com"),
						},
					},
				})
				if err != nil {
					t.Fatalf("marshalling subject: %s", err)
				}
				tmpl.RawSubject = rawSubject
			},
			want:       lint.Error,
			wantSubStr: "subject commonName value is not a string",
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
			name: "https_aia",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.IssuingCertificateURL = []string{"https://e99.i.lencr.org/"}
			},
			want:       lint.Error,
			wantSubStr: "authorityInformationAccess caIssuers URI is not an http URL",
		},
		{
			name: "aia_unparseable",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.IssuingCertificateURL = []string{"http://e99.i.lencr.org/%zz"}
			},
			want:       lint.Error,
			wantSubStr: "authorityInformationAccess caIssuers URI is not an http URL",
		},
		{
			name: "aia_no_hostname",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.IssuingCertificateURL = []string{"http:///e99.crt"}
			},
			want:       lint.Error,
			wantSubStr: "authorityInformationAccess caIssuers URI hostname is not a domain under a public suffix",
		},
		{
			name: "aia_bad_tld",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.IssuingCertificateURL = []string{"http://e99.i.lencr.invalid/"}
			},
			want:       lint.Error,
			wantSubStr: "authorityInformationAccess caIssuers URI hostname is not a domain under a public suffix",
		},
		{
			name: "https_crldp",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.CRLDistributionPoints = []string{"https://e99.c.lencr.org/1.crl"}
			},
			want:       lint.Error,
			wantSubStr: "crlDistributionPoints URI is not an http URL",
		},
		{
			name: "crldp_unparseable",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				tmpl.CRLDistributionPoints = []string{"http://e99.c.lencr.org/%zz"}
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
				tmpl.CRLDistributionPoints = []string{"http://e99.c.lencr.invalid/1.crl"}
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
			// 2^2046 has a bit length of 2047, but still encodes in 256
			// octets, so its encoded modulus size is 2048 bits: it passes the
			// size check and fails the parity check instead.
			name:       "rsa_modulus_leading_zero_bit",
			pub:        &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2046), E: 65537},
			want:       lint.Error,
			wantSubStr: "RSA modulus is even",
		},
		{
			// 2^2039 encodes in 255 octets, so its encoded modulus size is
			// 2040 bits.
			name:       "rsa_modulus_wrong_encoded_size",
			pub:        &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2039), E: 65537},
			want:       lint.Error,
			wantSubStr: "RSA encoded modulus size 2040 is not allowed",
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
			name: "critical_sct_list",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				criticalizeExt(t, tmpl, asn1.ObjectIdentifier(sctListOID))
			},
			want:       lint.Error,
			wantSubStr: "signedCertificateTimestampList extension is critical",
		},
		{
			name: "duplicate_extension",
			mod: func(t *testing.T, tmpl *x509.Certificate) {
				duplicateExt(t, tmpl, asn1.ObjectIdentifier(keyUsageOID))
			},
			want:       lint.Error,
			wantSubStr: "duplicate extension 2.5.29.15",
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

			pub := crypto.PublicKey(testKey(t, elliptic.P256()).Public())
			if tc.pub != nil {
				pub = tc.pub
			}
			tmpl := testLeafTemplate(t)
			if tc.name == "good_with_skid" {
				tmpl.SubjectKeyId = testRFC7093SKID(t, pub)
			}
			if tc.mod != nil {
				tc.mod(t, tmpl)
			}

			der, err := x509.CreateCertificate(rand.Reader, tmpl, intTmpl, pub, intKey)
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
