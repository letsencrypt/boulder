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

// coveringIdentifiers returns the set of "covering" identifiers used to enforce
// the CertificatesPerDomain rate limit. For DNS names, this is the eTLD+1 as
// determined by the Public Suffix List; exact public suffix matches are
// preserved. For IP addresses, the covering prefix is /32 for IPv4 and /64 for
// IPv6. This groups requests by registered domain or address block to match the
// scope of the limit. The result is deduplicated and lowercased. If the
// identifier type is unsupported, an error is returned.
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

// coveringIdentifier returns the "covering" identifier used to enforce the
// CertificatesPerDomain, CertificatesPerDomainPerAccount, and
// NewRegistrationsPerIPv6Range rate limits. For DNS names, this is the eTLD+1
// as determined by the Public Suffix List; exact public suffix matches are
// preserved. For IP addresses, the covering prefix depends on the limit:
//
// - CertificatesPerDomain and CertificatesPerDomainPerAccount:
//   - /32 for IPv4
//   - /64 for IPv6
//
// - NewRegistrationsPerIPv6Range:
//   - /48 for IPv6 only
//
// This groups requests by registered domain or address block to match the scope
// of each limit. The result is deduplicated and lowercased. If the identifier
// type or limit is unsupported, an error is returned.
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
		prefix, err := coveringIPPrefix(limit, ip)
		if err != nil {
			return "", err
		}
		return prefix.String(), nil
	}
	return "", fmt.Errorf("unsupported identifier type: %s", ident.Type)
}

// coveringIPPrefix returns the "covering" IP prefix used to enforce the
// CertificatesPerDomain, CertificatesPerDomainPerAccount, and
// NewRegistrationsPerIPv6Range rate limits. The prefix length depends on the
// limit and IP version:
//
// - CertificatesPerDomain and CertificatesPerDomainPerAccount:
//   - /32 for IPv4
//   - /64 for IPv6
//
// - NewRegistrationsPerIPv6Range:
//   - /48 for IPv6 only
//
// This groups requests by address block to match the scope of each limit. If
// the limit does not require a covering prefix, an error is returned.
func coveringIPPrefix(limit Name, addr netip.Addr) (netip.Prefix, error) {
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
