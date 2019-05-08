// The identifier package defines types for RFC 8555 ACME identifiers.
package identifier

// IdentifierType is a named string type for registered ACME identifier types.
// See https://tools.ietf.org/html/rfc8555#section-9.7.7
type IdentifierType string

const (
	// IdentifierDNS is specified in RFC 8555 for DNS identifiers.
	IdentifierDNS = IdentifierType("dns")
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

// TODO(@cpu): DNSIdentifier doc string
func DNSIdentifier(value string) ACMEIdentifier {
	return ACMEIdentifier{
		Type:  IdentifierDNS,
		Value: value,
	}
}
