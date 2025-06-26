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
// suffix matches are included. For IP address identifiers, this is the address
// (/32) for IPv4, or the /64 prefix for IPv6, in CIDR notation.
func coveringIdentifiers(idents identifier.ACMEIdentifiers) ([]string, error) {
	var covers []string
	for _, ident := range idents {
		cover, err := coveringIdentifier(ident)
		if err != nil {
			return nil, err
		}
		covers = append(covers, cover)
	}
	return core.UniqueLowerNames(covers), nil
}

// coveringIdentifier transforms a single ACMEIdentifier into its "covering"
// identifier, for the CertificatesPerDomain and CertificatesPerDomainPerAccount
// limits. For DNS identifiers, this is the eTLD+1; exact public suffix matches
// are included. For IP address identifiers, this is the address (/32) for IPv4,
// or the /64 prefix for IPv6, in CIDR notation.
func coveringIdentifier(ident identifier.ACMEIdentifier) (string, error) {
	switch ident.Type {
	case identifier.TypeDNS:
		domain, err := publicsuffix.Domain(ident.Value)
		if err != nil {
			if err.Error() == fmt.Sprintf("%s is a suffix", ident.Value) {
				// If the public suffix is the domain itself, that's fine.
				// Include the original name in the result.
				return ident.Value, nil
			}
			return "", err
		}
		return domain, nil
	case identifier.TypeIP:
		ip, err := netip.ParseAddr(ident.Value)
		if err != nil {
			return "", err
		}
		prefix, err := coveringPrefix(ip)
		if err != nil {
			return "", err
		}
		return prefix.String(), nil
	}
	return "", fmt.Errorf("unsupported identifier type: %s", ident.Type)
}

// coveringPrefix transforms a netip.Addr into its "covering" prefix, for the
// CertificatesPerDomain limit. For IPv4, this is the IP address (/32). For
// IPv6, this is the /64 that contains the address.
func coveringPrefix(addr netip.Addr) (netip.Prefix, error) {
	var bits int
	if addr.Is4() {
		bits = 32
	} else {
		bits = 64
	}
	prefix, err := addr.Prefix(bits)
	if err != nil {
		// This should be impossible because bits is hardcoded.
		return netip.Prefix{}, err
	}
	return prefix, nil
}
