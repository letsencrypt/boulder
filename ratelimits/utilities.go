package ratelimits

import (
	"strings"

	"github.com/weppos/publicsuffix-go/publicsuffix"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/identifier"
)

// joinWithColon joins the provided args with a colon.
func joinWithColon(args ...string) string {
	return strings.Join(args, ":")
}

// IdentifiersToETLDsPlusOne transforms a list of identifiers' values from FQDNs
// into de-duplicated eTLD+1's for the CertificatesPerDomain limit. Exact public
// suffix matches are included. IP addresses are retained as-is.
//
// TODO(#7961): Make this return a slice of strings, like it did before, and
// just discard IP identifiers.
func IdentifiersToETLDsPlusOne(idents []identifier.ACMEIdentifier) []identifier.ACMEIdentifier {
	var fqdns []string
	var results []identifier.ACMEIdentifier
	for _, ident := range idents {
		if ident.Type == identifier.TypeDNS {
			domain, err := publicsuffix.Domain(ident.Value)
			if err != nil {
				// The only possible errors are:
				// (1) publicsuffix.Domain is giving garbage values
				// (2) the public suffix is the domain itself
				// We assume 2 and include the original name in the result.
				fqdns = append(fqdns, ident.Value)
			} else {
				fqdns = append(fqdns, domain)
			}
		} else {
			results = append(results, ident)
		}
	}
	for _, fqdn := range core.UniqueLowerNames(fqdns) {
		results = append(results, identifier.NewDNS(fqdn))
	}
	return identifier.Normalize(results)
}
