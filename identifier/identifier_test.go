package identifier

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/netip"
	"slices"
	"testing"
)

// TestFromX509 tests FromCert and FromCSR, which are fromX509's public
// wrappers.
func TestFromX509(t *testing.T) {
	cases := []struct {
		name        string
		subject     pkix.Name
		dnsNames    []string
		ipAddresses []net.IP
		want        []ACMEIdentifier
	}{
		{
			name:     "no explicit CN",
			dnsNames: []string{"a.com"},
			want:     []ACMEIdentifier{NewDNS("a.com")},
		},
		{
			name:     "explicit uppercase CN",
			subject:  pkix.Name{CommonName: "A.com"},
			dnsNames: []string{"a.com"},
			want:     []ACMEIdentifier{NewDNS("a.com")},
		},
		{
			name:     "no explicit CN, uppercase SAN",
			dnsNames: []string{"A.com"},
			want:     []ACMEIdentifier{NewDNS("a.com")},
		},
		{
			name:     "duplicate SANs",
			dnsNames: []string{"b.com", "b.com", "a.com", "a.com"},
			want:     []ACMEIdentifier{NewDNS("a.com"), NewDNS("b.com")},
		},
		{
			name:     "explicit CN not found in SANs",
			subject:  pkix.Name{CommonName: "a.com"},
			dnsNames: []string{"b.com"},
			want:     []ACMEIdentifier{NewDNS("a.com"), NewDNS("b.com")},
		},
		{
			name:        "mix of DNSNames and IPAddresses",
			dnsNames:    []string{"a.com"},
			ipAddresses: []net.IP{{192, 168, 1, 1}},
			want:        []ACMEIdentifier{NewDNS("a.com"), NewIP(netip.MustParseAddr("192.168.1.1"))},
		},
	}
	for _, tc := range cases {
		t.Run("cert/"+tc.name, func(t *testing.T) {
			t.Parallel()
			got := FromCert(&x509.Certificate{Subject: tc.subject, DNSNames: tc.dnsNames, IPAddresses: tc.ipAddresses})
			if !slices.Equal(got, tc.want) {
				t.Errorf("FromCert() got %#v, but want %#v", got, tc.want)
			}
		})
		t.Run("csr/"+tc.name, func(t *testing.T) {
			t.Parallel()
			got := FromCSR(&x509.CertificateRequest{Subject: tc.subject, DNSNames: tc.dnsNames, IPAddresses: tc.ipAddresses})
			if !slices.Equal(got, tc.want) {
				t.Errorf("FromCSR() got %#v, but want %#v", got, tc.want)
			}
		})
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		name   string
		idents []ACMEIdentifier
		want   []ACMEIdentifier
	}{
		{
			name: "convert to lowercase",
			idents: []ACMEIdentifier{
				{Type: TypeDNS, Value: "AlPha.example.coM"},
				{Type: TypeIP, Value: "fe80::CAFE"},
			},
			want: []ACMEIdentifier{
				{Type: TypeDNS, Value: "alpha.example.com"},
				{Type: TypeIP, Value: "fe80::cafe"},
			},
		},
		{
			name: "sort",
			idents: []ACMEIdentifier{
				{Type: TypeDNS, Value: "foobar.com"},
				{Type: TypeDNS, Value: "bar.com"},
				{Type: TypeDNS, Value: "baz.com"},
				{Type: TypeDNS, Value: "a.com"},
				{Type: TypeIP, Value: "fe80::cafe"},
				{Type: TypeIP, Value: "2001:db8::1dea"},
				{Type: TypeIP, Value: "192.168.1.1"},
			},
			want: []ACMEIdentifier{
				{Type: TypeDNS, Value: "a.com"},
				{Type: TypeDNS, Value: "bar.com"},
				{Type: TypeDNS, Value: "baz.com"},
				{Type: TypeDNS, Value: "foobar.com"},
				{Type: TypeIP, Value: "192.168.1.1"},
				{Type: TypeIP, Value: "2001:db8::1dea"},
				{Type: TypeIP, Value: "fe80::cafe"},
			},
		},
		{
			name: "de-duplicate",
			idents: []ACMEIdentifier{
				{Type: TypeDNS, Value: "AlPha.example.coM"},
				{Type: TypeIP, Value: "fe80::CAFE"},
				{Type: TypeDNS, Value: "alpha.example.com"},
				{Type: TypeIP, Value: "fe80::cafe"},
				NewIP(netip.MustParseAddr("fe80:0000:0000:0000:0000:0000:0000:cafe")),
			},
			want: []ACMEIdentifier{
				{Type: TypeDNS, Value: "alpha.example.com"},
				{Type: TypeIP, Value: "fe80::cafe"},
			},
		},
		{
			name: "DNS before IP",
			idents: []ACMEIdentifier{
				{Type: TypeIP, Value: "fe80::cafe"},
				{Type: TypeDNS, Value: "alpha.example.com"},
			},
			want: []ACMEIdentifier{
				{Type: TypeDNS, Value: "alpha.example.com"},
				{Type: TypeIP, Value: "fe80::cafe"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Normalize(tc.idents)
			if !slices.Equal(got, tc.want) {
				t.Errorf("Got %#v, but want %#v", got, tc.want)
			}
		})
	}
}
