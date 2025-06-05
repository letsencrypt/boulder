package ratelimits

import (
	"fmt"
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

// coveringIdentifiers transforms a slice of ACMEIdentifiers into strings of
// their "covering" identifiers, for the CertificatesPerDomain limit. It also
// de-duplicates the output. For DNS identifiers, this is eTLD+1's; exact public
// suffix matches are included. For IP address identifiers, this is the /24 (for
// IPv4) or /48 (for IPv6) that contains them.
func coveringIdentifiers(idents identifier.ACMEIdentifiers) ([]string, error) {
	var covers []string
	for _, ident := range idents {
		switch ident.Type {
		case identifier.TypeDNS:
			domain, err := publicsuffix.Domain(ident.Value)
			if err != nil {
				if err.Error() == fmt.Sprintf("%s is a suffix", ident.Value) {
					// If the public suffix is the domain itself, that's fine.
					// Include the original name in the result.
					covers = append(covers, ident.Value)
					continue
				} else {
					return nil, err
				}
			}
			covers = append(covers, domain)
		case identifier.TypeIP:
			ip, err := netip.ParseAddr(ident.Value)
			if err != nil {
				return nil, err
			}
			var bits int
			if ip.Is4() {
				bits = 24
			} else {
				bits = 48
			}
			prefix, err := ip.Prefix(bits)
			if err != nil {
				return nil, err
			}
			covers = append(covers, prefix.String())
		}
	}
	return core.UniqueLowerNames(covers), nil
}
