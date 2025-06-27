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
		cover, err := coveringIdentifier(CertificatesPerDomain, ident)
		if err != nil {
			return nil, err
		}
		covers = append(covers, cover)
	}
	return core.UniqueLowerNames(covers), nil
}

// coveringIdentifier transforms a single ACMEIdentifier into its "covering"
// identifier, for the CertificatesPerDomain, CertificatesPerDomainPerAccount,
// and NewRegistrationsPerIPv6Range limits. For DNS identifiers, this is the
// eTLD+1; exact public suffix matches are included. For IP address identifiers,
// this is the address (/32) for IPv4, or the /64 prefix for IPv6, in CIDR
// notation.
func coveringIdentifier(limit Name, ident identifier.ACMEIdentifier) (string, error) {
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
		prefix, err := coveringPrefix(limit, ip)
		if err != nil {
			return "", err
		}
		return prefix.String(), nil
	}
	return "", fmt.Errorf("unsupported identifier type: %s", ident.Type)
}

// coveringPrefix transforms a netip.Addr into its "covering" prefix, for the
// CertificatesPerDomain, CertificatesPerDomainPerAccount, and
// NewRegistrationsPerIPv6Range limits.
func coveringPrefix(limit Name, addr netip.Addr) (netip.Prefix, error) {
	switch limit {
	case CertificatesPerDomain, CertificatesPerDomainPerAccount:
		var bits int
		if addr.Is4() {
			bits = 32
		} else {
			bits = 64
		}
		prefix, err := addr.Prefix(bits)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("building covering prefix for %s: %w", addr, err)
		}
		return prefix, nil

	case NewRegistrationsPerIPv6Range:
		if !addr.Is6() {
			return netip.Prefix{}, fmt.Errorf("limit %s requires an IPv6 address, got %s", limit, addr)
		}
		prefix, err := addr.Prefix(48)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("building covering prefix for %s: %w", addr, err)
		}
		return prefix, nil
	}
	return netip.Prefix{}, fmt.Errorf("limit %s does not require a covering prefix", limit)
}
