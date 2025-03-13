package identifier

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/netip"
	"testing"

	corepb "github.com/letsencrypt/boulder/core/proto"
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

type protoToProtoTestCases struct {
	Name         string
	InputIdents  []*corepb.Identifier
	InputNames   []string
	ExpectIdents []ACMEIdentifier
}

func (tc protoToProtoTestCases) GetIdentifiers() []*corepb.Identifier {
	return tc.InputIdents
}

func (tc protoToProtoTestCases) GetDnsNames() []string {
	return tc.InputNames
}

func TestProtoToProtoWithDefault(t *testing.T) {
	testCases := []protoToProtoTestCases{
		{
			Name: "Populated identifiers, populated names, same values",
			InputIdents: []*corepb.Identifier{
				{Type: "dns", Value: "a.example.com"},
				{Type: "dns", Value: "b.example.com"},
			},
			InputNames: []string{"a.example.com", "b.example.com"},
			ExpectIdents: []ACMEIdentifier{
				{Type: TypeDNS, Value: "a.example.com"},
				{Type: TypeDNS, Value: "b.example.com"},
			},
		},
		{
			Name: "Populated identifiers, populated names, different values",
			InputIdents: []*corepb.Identifier{
				{Type: "dns", Value: "coffee.example.com"},
			},
			InputNames: []string{"tea.example.com"},
			ExpectIdents: []ACMEIdentifier{
				{Type: TypeDNS, Value: "coffee.example.com"},
			},
		},
		{
			Name: "Populated identifiers, empty names",
			InputIdents: []*corepb.Identifier{
				{Type: "dns", Value: "example.com"},
			},
			InputNames: []string{},
			ExpectIdents: []ACMEIdentifier{
				{Type: TypeDNS, Value: "example.com"},
			},
		},
		{
			Name: "Populated identifiers, nil names",
			InputIdents: []*corepb.Identifier{
				{Type: "dns", Value: "example.com"},
			},
			InputNames: nil,
			ExpectIdents: []ACMEIdentifier{
				{Type: TypeDNS, Value: "example.com"},
			},
		},
		{
			Name:        "Empty identifiers, populated names",
			InputIdents: []*corepb.Identifier{},
			InputNames:  []string{"a.example.com", "b.example.com"},
			ExpectIdents: []ACMEIdentifier{
				{Type: TypeDNS, Value: "a.example.com"},
				{Type: TypeDNS, Value: "b.example.com"},
			},
		},
		{
			Name:         "Empty identifiers, empty names",
			InputIdents:  []*corepb.Identifier{},
			InputNames:   []string{},
			ExpectIdents: nil,
		},
		{
			Name:         "Empty identifiers, nil names",
			InputIdents:  []*corepb.Identifier{},
			InputNames:   nil,
			ExpectIdents: nil,
		},
		{
			Name:        "Nil identifiers, populated names",
			InputIdents: nil,
			InputNames:  []string{"a.example.com", "b.example.com"},
			ExpectIdents: []ACMEIdentifier{
				{Type: TypeDNS, Value: "a.example.com"},
				{Type: TypeDNS, Value: "b.example.com"},
			},
		},
		{
			Name:         "Nil identifiers, empty names",
			InputIdents:  nil,
			InputNames:   []string{},
			ExpectIdents: nil,
		},
		{
			Name:         "Nil identifiers, nil names",
			InputIdents:  nil,
			InputNames:   nil,
			ExpectIdents: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			test.AssertDeepEquals(t, SliceFromProto(WithDefaults(tc)), tc.ExpectIdents)
		})
	}
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
			[]ACMEIdentifier{FromDNS("a.com")},
		},
		{
			"explicit uppercase CN",
			&x509.CertificateRequest{Subject: pkix.Name{CommonName: "A.com"}, DNSNames: []string{"a.com"}},
			[]ACMEIdentifier{FromDNS("a.com")},
		},
		{
			"no explicit CN, uppercase SAN",
			&x509.CertificateRequest{DNSNames: []string{"A.com"}},
			[]ACMEIdentifier{FromDNS("a.com")},
		},
		{
			"duplicate SANs",
			&x509.CertificateRequest{DNSNames: []string{"b.com", "b.com", "a.com", "a.com"}},
			[]ACMEIdentifier{FromDNS("a.com"), FromDNS("b.com")},
		},
		{
			"explicit CN not found in SANs",
			&x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.com"}, DNSNames: []string{"b.com"}},
			[]ACMEIdentifier{FromDNS("a.com"), FromDNS("b.com")},
		},
		{
			"mix of DNSNames and IPAddresses",
			&x509.CertificateRequest{DNSNames: []string{"a.com"}, IPAddresses: []net.IP{{192, 168, 1, 1}}},
			[]ACMEIdentifier{FromDNS("a.com"), FromIP(netip.MustParseAddr("192.168.1.1"))},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			test.AssertDeepEquals(t, FromCSR(tc.csr), tc.expectedIdents)
		})
	}
}
