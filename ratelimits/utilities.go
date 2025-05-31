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
