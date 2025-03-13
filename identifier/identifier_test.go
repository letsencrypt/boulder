package identifier

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/netip"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestNormalize(t *testing.T) {
	idents := []ACMEIdentifier{
		{Type: "DNS", Value: "foobar.com"},
		{Type: "DNS", Value: "fooBAR.com"},
		{Type: "DNS", Value: "baz.com"},
		{Type: "DNS", Value: "foobar.com"},
		{Type: "DNS", Value: "bar.com"},
		{Type: "DNS", Value: "bar.com"},
		{Type: "DNS", Value: "a.com"},
	}
	expected := []ACMEIdentifier{
		{Type: "DNS", Value: "a.com"},
		{Type: "DNS", Value: "bar.com"},
		{Type: "DNS", Value: "baz.com"},
		{Type: "DNS", Value: "foobar.com"},
	}
	u := Normalize(idents)
	test.AssertDeepEquals(t, expected, u)
}

// TestFromCSR covers TestFromCert as well, because their logic is exactly the same.
func TestFromCSR(t *testing.T) {
	cases := []struct {
		name           string
		csr            *x509.CertificateRequest
		expectedIdents []ACMEIdentifier
	}{
		{
			"no explicit CN",
			&x509.CertificateRequest{DNSNames: []string{"a.com"}},
			[]ACMEIdentifier{NewDNS("a.com")},
		},
		{
			"explicit uppercase CN",
			&x509.CertificateRequest{Subject: pkix.Name{CommonName: "A.com"}, DNSNames: []string{"a.com"}},
			[]ACMEIdentifier{NewDNS("a.com")},
		},
		{
			"no explicit CN, uppercase SAN",
			&x509.CertificateRequest{DNSNames: []string{"A.com"}},
			[]ACMEIdentifier{NewDNS("a.com")},
		},
		{
			"duplicate SANs",
			&x509.CertificateRequest{DNSNames: []string{"b.com", "b.com", "a.com", "a.com"}},
			[]ACMEIdentifier{NewDNS("a.com"), NewDNS("b.com")},
		},
		{
			"explicit CN not found in SANs",
			&x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.com"}, DNSNames: []string{"b.com"}},
			[]ACMEIdentifier{NewDNS("a.com"), NewDNS("b.com")},
		},
		{
			"mix of DNSNames and IPAddresses",
			&x509.CertificateRequest{DNSNames: []string{"a.com"}, IPAddresses: []net.IP{{192, 168, 1, 1}}},
			[]ACMEIdentifier{NewDNS("a.com"), NewIP(netip.MustParseAddr("192.168.1.1"))},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			test.AssertDeepEquals(t, FromCSR(tc.csr), tc.expectedIdents)
		})
	}
}
