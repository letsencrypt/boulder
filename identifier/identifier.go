// The identifier package defines types for RFC 8555 ACME identifiers.
// It exists as a separate package to prevent an import loop between the core
// and probs packages.
package identifier

import (
	"crypto/x509"
	"fmt"
	"net"
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
//
// If the *corepb.Identifiers are empty or nil, then the second parameter, a
// slice of strings, is used to construct the result.
//
// TODO(#7311): The second parameter can be removed after DnsNames are no longer
// used in RPCs.
func SliceFromProto(pbIdents []*corepb.Identifier, names []string) []ACMEIdentifier {
	if len(pbIdents) == 0 {
		if len(names) == 0 {
			return nil
		}
		idents := make([]ACMEIdentifier, len(names))
		for key, name := range names {
			idents[key] = NewDNS(name)
		}
		return idents
	}

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
//
// TODO(#7961): A bunch of uses of this should be replaced with SliceFromProto,
// and a bunch of others should be replaced with FromCert or FromCSR.
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

// SliceNewIPs is a convenience function for creating a slice of ACMEIdentifiers
// with Type "ip" for a given slice of net.IPs.
//
// TODO(#7961): A bunch of uses of this should be replaced with SliceFromProto,
// and a bunch of others should be replaced with FromCert or FromCSR.
func SliceNewIPs(netIPs []net.IP) ([]ACMEIdentifier, error) {
	idents := make([]ACMEIdentifier, len(netIPs))
	for key, netIP := range netIPs {
		netipAddr, ok := netip.AddrFromSlice(netIP)
		if !ok {
			return nil, fmt.Errorf("converting IP from bytes: %s", netIP)
		}
		idents[key] = NewIP(netipAddr)
	}
	return idents, nil
}

// FromCert extracts the Subject Common Name and Subject Alternative Names from
// a certificate, and returns a slice of ACMEIdentifiers (or an error).
func FromCert(cert *x509.Certificate) ([]ACMEIdentifier, error) {
	// Produce a new "sans" slice with the same memory address as csr.DNSNames
	// but force a new allocation if an append happens so that we don't
	// accidentally mutate the underlying csr.DNSNames array.
	sans := cert.DNSNames[0:len(cert.DNSNames):len(cert.DNSNames)]
	if cert.Subject.CommonName != "" {
		sans = append(sans, cert.Subject.CommonName)
	}

	ips, err := SliceNewIPs(cert.IPAddresses)
	if err != nil {
		return nil, err
	}

	return NormalizeIdentifiers(append(SliceNewDNS(sans), ips...)), nil
}

// NormalizeIdentifiers returns the set of all unique ACME identifiers in the
// input after all of them are lowercased. The returned identifier values will
// be in their lowercased form and sorted alphabetically by value.
func NormalizeIdentifiers(idents []ACMEIdentifier) []ACMEIdentifier {
	for i := range idents {
		idents[i].Value = strings.ToLower(idents[i].Value)
	}

	sort.Slice(idents, func(i, j int) bool {
		return fmt.Sprintf("%s:%s", idents[i].Type, idents[i].Value) < fmt.Sprintf("%s:%s", idents[j].Type, idents[j].Value)
	})

	return slices.Compact(idents)
}
