// The identifier package defines types for RFC 8555 ACME identifiers.
package identifier

import (
	"net"
)

// IdentifierType is a named string type for registered ACME identifier types.
// See https://tools.ietf.org/html/rfc8555#section-9.7.7
type IdentifierType string

const (
	// DNS is specified in RFC 8555 for DNS type identifiers.
	DNS = IdentifierType("dns")
	// defined IP Identifiers as specified in draft-ietf-acme-ip-08: update when it becom RFC
	IP = IdentifierType("ip")
	// a placeholder onion Identifiers defined
	ONION = IdentifierType("onion")
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

// DNSIdentifier is a convenience function for creating an ACMEIdentifier with
// Type DNS for a given domain name.
func DNSIdentifier(domain string) ACMEIdentifier {
	return ACMEIdentifier{
		Type:  DNS,
		Value: domain,
	}
}

//a temporary function that create currect type of ACMEIdent from string,
// ultimately shoudn't called outside of test contaxt
func RecreateIdentifier(name string) ACMEIdentifier {
	if net.ParseIP(name) != nil {
		return ACMEIdentifier{
			Type:  IP,
			Value: name,
		}
	} else {
		return ACMEIdentifier{
			Type:  DNS,
			Value: name,
		}
	}
}
