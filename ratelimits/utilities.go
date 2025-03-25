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
// Exact public suffix matches are included.
func FQDNsToETLDsPlusOne(names []string) []string {
	var domains []string
	for _, name := range names {
		domain, err := publicsuffix.Domain(name)
		if err != nil {
			// The only possible errors are:
			// (1) publicsuffix.Domain is giving garbage values
			// (2) the public suffix is the domain itself
			// We assume 2 and include the original name in the result.
			domains = append(domains, name)
		} else {
			domains = append(domains, domain)
		}
	}
	return core.UniqueLowerNames(domains)
}

// hashNames returns a hash of the names requested. This is intended for use
// when interacting with the orderFqdnSets table and rate limiting.
//
// Deprecated: TODO(#7311): Use HashIdentifiers instead.
func hashNames(names []string) []byte {
	return core.HashIdentifiers(identifier.NewDNSSlice(names))
}
