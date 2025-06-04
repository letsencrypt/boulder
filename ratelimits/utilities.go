package ratelimits

import (
	"net/netip"
	"strings"

	"github.com/weppos/publicsuffix-go/publicsuffix"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/identifier"
)

// joinWithColon joins the provided args with a colon.
func joinWithColon(args ...string) string {
	return strings.Join(args, ":")
}

// FQDNsToETLDsPlusOne transforms a list of FQDNs into a list of eTLD+1's for
// the CertificatesPerDomain limit. It also de-duplicates the output domains.
// Exact public suffix matches are included. Non-DNS identifiers are ignored.
func FQDNsToETLDsPlusOne(idents identifier.ACMEIdentifiers) []string {
	var domains []string
	for _, ident := range idents {
		if ident.Type != identifier.TypeDNS {
			continue
		}
		domain, err := publicsuffix.Domain(ident.Value)
		if err != nil {
			// The only possible errors are:
			// (1) publicsuffix.Domain is giving garbage values
			// (2) the public suffix is the domain itself
			// We assume 2 and include the original name in the result.
			domains = append(domains, ident.Value)
		} else {
			domains = append(domains, domain)
		}
	}
	return core.UniqueLowerNames(domains)
}

// guessIdentifiers is a convenience function for creating a slice of
// ACMEIdentifier for a given slice of identifier values with unknown (and
// potentially mixed) types.
//
// Only use this when parsing input that cannot, or does not yet, distinguish
// between identifier types.
func guessIdentifiers(input []string) identifier.ACMEIdentifiers {
	var out identifier.ACMEIdentifiers
	for _, value := range input {
		ip, err := netip.ParseAddr(value)
		if err == nil {
			out = append(out, identifier.NewIP(ip))
		} else {
			out = append(out, identifier.NewDNS(value))
		}
	}
	return out
}
