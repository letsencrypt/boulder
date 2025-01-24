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

// SliceAsProto is a convenience function for converting a slice of
// ACMEIdentifiers into a slice of *corepb.Identifiers, to use for RPCs.
func SliceAsProto(idents []ACMEIdentifier) []*corepb.Identifier {
	pbIdents := make([]*corepb.Identifier, len(idents))
	for key, ident := range idents {
		pbIdents[key] = ident.AsProto()
	}
	return pbIdents
}

// SliceFromProto is a convenience function for converting a slice of
// *corepb.Identifiers from RPCs into a slice of ACMEIdentifiers.
func SliceFromProto(pbIdents []*corepb.Identifier) []ACMEIdentifier {
	idents := make([]ACMEIdentifier, len(pbIdents))
	for key, pbIdent := range pbIdents {
		idents[key] = FromProto(pbIdent)
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

// SliceNewDNS is a convenience function for creating a slice of ACMEIdentifiers
// with Type "dns" for a given slice of domain names.
func SliceNewDNS(domains []string) []ACMEIdentifier {
	idents := make([]ACMEIdentifier, len(domains))
	for key, domain := range domains {
		idents[key] = NewDNS(domain)
	}
	return idents
}

// NewIP is a convenience function for creating an ACMEIdentifier with Type "ip"
// for a given IP address.
func NewIP(ip netip.Addr) ACMEIdentifier {
	return ACMEIdentifier{
		Type:  TypeIP,
		Value: ip.StringExpanded(),
	}
}

// IdentifierAndName is a convenience function that takes a *corepb.Identifier
// and a string, and returns an ACMEIdentifier and a string. If either input is
// nil, its corresponding return value is constructed from the other's value.
//
// Deprecated: TODO(#7311): This can be removed after DnsNames are no longer
// used in RPCs.
func IdentifierAndName(pbIdent *corepb.Identifier, name string) (ACMEIdentifier, string) {
	if pbIdent.GetValue() == "" {
		if name == "" {
			return ACMEIdentifier{}, name
		}
		return NewDNS(name), name
	} else {
		if name == "" {
			name = pbIdent.GetValue()
		}
		return FromProto(pbIdent), name
	}
}

// IdentifiersAndNames is a convenience function that takes slices of
// *corepb.Identifier and string, and returns slices of ACMEIdentifier and
// string. If either input is nil, its corresponding return contents are
// constructed from the other's contents.
//
// Deprecated: TODO(#7311): This can be removed after DnsNames are no longer
// used in RPCs.
func IdentifiersAndNames(pbIdents []*corepb.Identifier, names []string) ([]ACMEIdentifier, []string) {
	if len(pbIdents) == 0 {
		idents := make([]ACMEIdentifier, len(names))
		for i, name := range names {
			idents[i] = NewDNS(name)
		}
		return idents, names
	} else {
		if len(names) == 0 {
			names = make([]string, len(pbIdents))
			for i, pbIdent := range pbIdents {
				names[i] = pbIdent.GetValue()
			}
		}
		return SliceFromProto(pbIdents), names
	}
}
