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

// TODO(#7311): This can be removed after DnsNames are no longer used in RPCs.
func FromProtoWithDefault(ident *corepb.Identifier, name string) ACMEIdentifier {
	if ident == nil {
		return NewDNS(name)
	}
	return FromProto(ident)
}

// SliceAsProto is a convenience function for converting a slice of
// ACMEIdentifiers into a slice of *corepb.Identifiers, to use for RPCs.
func SliceAsProto(idents []ACMEIdentifier) []*corepb.Identifier {
	var pbIdents []*corepb.Identifier
	for _, ident := range idents {
		pbIdents = append(pbIdents, ident.AsProto())
	}
	return pbIdents
}

// SliceFromProto is a convenience function for converting a slice of
// *corepb.Identifiers from RPCs into a slice of ACMEIdentifiers.
//
// If the *corepb.Identifiers are empty or nil, then the second parameter, a
// slice of strings, is used to construct the result.
//
// TODO(#7311): The second parameter can be removed after DnsNames are no longer
// used in RPCs.
func SliceFromProto(pbIdents []*corepb.Identifier, names []string) []ACMEIdentifier {
	var idents []ACMEIdentifier

	if len(pbIdents) == 0 {
		for _, name := range names {
			idents = append(idents, NewDNS(name))
		}
		return idents
	}

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

// NewIP is a convenience function for creating an ACMEIdentifier with Type "ip"
// for a given IP address.
func NewIP(ip netip.Addr) ACMEIdentifier {
	return ACMEIdentifier{
		Type:  TypeIP,
		Value: ip.StringExpanded(),
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
