// The identifier package defines types for RFC 8555 ACME identifiers.
// It exists as a separate package to prevent an import loop between the core
// and probs packages.
package identifier

import (
	"net/netip"

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

func (i ACMEIdentifier) AsProto() *corepb.Identifier {
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

// FromProtoWithDefault can be removed after DnsNames are no longer used in
// RPCs. TODO(#8023)
func FromProtoWithDefault(ident *corepb.Identifier, name string) ACMEIdentifier {
	if ident == nil {
		return NewDNS(name)
	}
	return FromProto(ident)
}

// NewDNS is a convenience function for creating an ACMEIdentifier with Type
// "dns" for a given domain name.
func NewDNS(domain string) ACMEIdentifier {
	return ACMEIdentifier{
		Type:  TypeDNS,
		Value: domain,
	}
}

// FromDNSNames is a convenience function for creating a slice of ACMEIdentifier
// with Type "dns" for a given slice of domain names.
func FromDNSNames(input []string) []ACMEIdentifier {
	var out []ACMEIdentifier
	for _, in := range input {
		out = append(out, NewDNS(in))
	}
	return out
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
