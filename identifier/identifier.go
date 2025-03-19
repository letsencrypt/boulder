// The identifier package defines types for RFC 8555 ACME identifiers.
// It exists as a separate package to prevent an import loop between the core
// and probs packages.
package identifier

import (
	"crypto/x509"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	corepb "github.com/letsencrypt/boulder/core/proto"
)

// IdentifierType is a named string type for registered ACME identifier types.
// See https://tools.ietf.org/html/rfc8555#section-9.7.7
type IdentifierType string

const (
	// TypeDNS is specified in RFC 8555 for TypeDNS type identifiers.
	TypeDNS = IdentifierType("dns")
	// TypeIP is specified in RFC 8738
	TypeIP = IdentifierType("ip")
)

// ACMEIdentifier is a struct encoding an identifier that can be validated. The
// protocol allows for different types of identifier to be supported (DNS
// names, IP addresses, etc.), but currently we only support RFC 8555 DNS type
// identifiers for domain names.
type ACMEIdentifier struct {
	// Type is the registered IdentifierType of the identifier.
	Type IdentifierType `json:"type"`
	// Value is the value of the identifier. For a DNS type identifier it is
	// a domain name.
	Value string `json:"value"`
}

func (i ACMEIdentifier) ToProto() *corepb.Identifier {
	return &corepb.Identifier{
		Type:  string(i.Type),
		Value: i.Value,
	}
}

func FromProto(ident *corepb.Identifier) ACMEIdentifier {
	return ACMEIdentifier{
		Type:  IdentifierType(ident.Type),
		Value: ident.Value,
	}
}

// SliceAsProto is a convenience function for converting a slice of
// ACMEIdentifier into a slice of *corepb.Identifier, to use for RPCs.
func SliceAsProto(idents []ACMEIdentifier) []*corepb.Identifier {
	var pbIdents []*corepb.Identifier
	for _, ident := range idents {
		pbIdents = append(pbIdents, ident.ToProto())
	}
	return pbIdents
}

// SliceFromProto is a convenience function for converting a slice of
// *corepb.Identifier from RPCs into a slice of ACMEIdentifier.
func SliceFromProto(pbIdents []*corepb.Identifier) []ACMEIdentifier {
	var idents []ACMEIdentifier

	for _, pbIdent := range pbIdents {
		idents = append(idents, FromProto(pbIdent))
	}
	return idents
}

// NewDNS is a convenience function for creating an ACMEIdentifier with Type
// "dns" for a given domain name.
func NewDNS(domain string) ACMEIdentifier {
	return ACMEIdentifier{
		Type:  TypeDNS,
		Value: domain,
	}
}

// NewDNSSlice is a convenience function for creating a slice of ACMEIdentifier
// with Type "dns" for a given slice of domain names.
func NewDNSSlice(input []string) []ACMEIdentifier {
	var out []ACMEIdentifier
	for _, in := range input {
		out = append(out, NewDNS(in))
	}
	return out
}

// AsDNSNames returns a list of DNS names from the input, if the input contains
// only DNS identifiers. Otherwise, it returns an error.
func AsDNSNames(input []ACMEIdentifier) ([]string, error) {
	var out []string
	for _, in := range input {
		if in.Type != "dns" {
			return nil, fmt.Errorf("identifier '%s' is of type '%s', not DNS", in.Value, in.Type)
		}
		out = append(out, in.Value)
	}
	return out, nil
}

// NewIP is a convenience function for creating an ACMEIdentifier with Type "ip"
// for a given IP address.
func NewIP(ip netip.Addr) ACMEIdentifier {
	return ACMEIdentifier{
		Type: TypeIP,
		// RFC 8738, Sec. 3: The identifier value MUST contain the textual form
		// of the address as defined in RFC 1123, Sec. 2.1 for IPv4 and in RFC
		// 5952, Sec. 4 for IPv6.
		Value: ip.String(),
	}
}

// FromCert extracts the Subject Alternative Names from a certificate, and
// returns a slice of ACMEIdentifiers and an error. It does not extract the
// Subject Common Name.
//
// FromCSR is similar but handles CSRs, and is kept separate so that it's always
// clear we are handling an untrusted CSR.
func FromCert(cert *x509.Certificate) []ACMEIdentifier {
	var sans []ACMEIdentifier
	for _, name := range cert.DNSNames {
		sans = append(sans, NewDNS(name))
	}

	for _, ip := range cert.IPAddresses {
		sans = append(sans, ACMEIdentifier{
			Type:  TypeIP,
			Value: ip.String(),
		})
	}

	return Normalize(sans)
}

// FromCSR extracts the Subject Common Name and Subject Alternative Names from a
// CSR, and returns a slice of ACMEIdentifiers and an error.
//
// FromCert is similar but handles certs, and is kept separate so that it's
// always clear we are handling an untrusted CSR.
func FromCSR(csr *x509.CertificateRequest) []ACMEIdentifier {
	var sans []ACMEIdentifier
	for _, name := range csr.DNSNames {
		sans = append(sans, NewDNS(name))
	}
	if csr.Subject.CommonName != "" {
		// Boulder won't generate certificates with a CN that's not also present
		// in the SANs, but such a certificate is possible. If appended, this is
		// deduplicated later with Normalize(). We assume the CN is a DNSName,
		// because CNs are untyped strings without metadata, and we will never
		// configure a Boulder profile to issue a certificate that contains both
		// an IP address identifier and a CN.
		sans = append(sans, NewDNS(csr.Subject.CommonName))
	}

	for _, ip := range csr.IPAddresses {
		sans = append(sans, ACMEIdentifier{
			Type:  TypeIP,
			Value: ip.String(),
		})
	}

	return Normalize(sans)
}

// Normalize returns the set of all unique ACME identifiers in the
// input after all of them are lowercased. The returned identifier values will
// be in their lowercased form and sorted alphabetically by value.
func Normalize(idents []ACMEIdentifier) []ACMEIdentifier {
	for i := range idents {
		idents[i].Value = strings.ToLower(idents[i].Value)
	}

	sort.Slice(idents, func(i, j int) bool {
		return fmt.Sprintf("%s:%s", idents[i].Type, idents[i].Value) < fmt.Sprintf("%s:%s", idents[j].Type, idents[j].Value)
	})

	return slices.Compact(idents)
}

type HasIdentifier interface {
	GetIdentifier() *corepb.Identifier
	GetDnsName() string
}

// WithDefault can be removed after DnsNames are no longer used in RPCs.
// TODO(#8023)
func WithDefault(input HasIdentifier) *corepb.Identifier {
	if input.GetIdentifier() != nil {
		return input.GetIdentifier()
	}
	return NewDNS(input.GetDnsName()).ToProto()
}

type HasIdentifiers interface {
	GetIdentifiers() []*corepb.Identifier
	GetDnsNames() []string
}

// WithDefaults can be removed after DnsNames are no longer used in
// RPCs. TODO(#8023)
func WithDefaults(input HasIdentifiers) []*corepb.Identifier {
	if len(input.GetIdentifiers()) > 0 {
		return input.GetIdentifiers()
	}
	return SliceAsProto(NewDNSSlice(input.GetDnsNames()))
}
