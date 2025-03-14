// The identifier package defines types and functions for handling plural RFC
// 8555 ACME identifiers. It exists as a separate package to prevent an import
// loop between the core and probs packages, and to improve code readability so
// that it's clear when you're calling a function to handle/return a slice of
// identifiers, as opposed to a single identifier.
package identifiers

import (
	//	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/identifier"
)

// ACMEIdentifiers is a named type for a slice of ACME identifiers, so that
// methods can be applied to these slices.
type ACMEIdentifiers []identifier.ACMEIdentifier

// FromDNS is a convenience function for creating a slice of ACMEIdentifier with
// Type "dns" for a given slice of domain names.
func FromDNS(input []string) ACMEIdentifiers {
	var out ACMEIdentifiers
	for _, in := range input {
		out = append(out, identifier.FromDNS(in))
	}
	return out
}
