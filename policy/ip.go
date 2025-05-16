package policy

import (
	"net"
	"net/netip"
	"strings"
)

var (
	// TODO(#8040): Rebuild these as structs that track the structure of IANA's
	// CSV files, for better automated handling.
	//
	// Private CIDRs to ignore. Sourced from:
	// https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
	privateV4Prefixes = map[netip.Prefix]string{
		netip.MustParsePrefix("0.0.0.0/8"):          "RFC 791, Section 3.2: This network",
		netip.MustParsePrefix("0.0.0.0/32"):         "RFC 1122, Section 3.2.1.3: This host on this network",
		netip.MustParsePrefix("10.0.0.0/8"):         "RFC 1918: Private-Use",
		netip.MustParsePrefix("100.64.0.0/10"):      "RFC 6598: Shared Address Space",
		netip.MustParsePrefix("127.0.0.0/8"):        "RFC 1122, Section 3.2.1.3: Loopback",
		netip.MustParsePrefix("169.254.0.0/16"):     "RFC 3927: Link Local",
		netip.MustParsePrefix("172.16.0.0/12"):      "RFC 1918: Private-Use",
		netip.MustParsePrefix("192.0.0.0/24"):       "RFC 6890, Section 2.1: IETF Protocol Assignments",
		netip.MustParsePrefix("192.0.0.0/29"):       "RFC 7335: IPv4 Service Continuity Prefix",
		netip.MustParsePrefix("192.0.0.8/32"):       "RFC 7600: IPv4 dummy address",
		netip.MustParsePrefix("192.0.0.9/32"):       "RFC 7723: Port Control Protocol Anycast",
		netip.MustParsePrefix("192.0.0.10/32"):      "RFC 8155: Traversal Using Relays around NAT Anycast",
		netip.MustParsePrefix("192.0.0.170/32"):     "RFC 8880 & RFC 7050, Section 2.2: NAT64/DNS64 Discovery",
		netip.MustParsePrefix("192.0.0.171/32"):     "RFC 8880 & RFC 7050, Section 2.2: NAT64/DNS64 Discovery",
		netip.MustParsePrefix("192.0.2.0/24"):       "RFC 5737: Documentation (TEST-NET-1)",
		netip.MustParsePrefix("192.31.196.0/24"):    "RFC 7535: AS112-v4",
		netip.MustParsePrefix("192.52.193.0/24"):    "RFC 7450: AMT",
		netip.MustParsePrefix("192.88.99.0/24"):     "RFC 7526: Deprecated (6to4 Relay Anycast)",
		netip.MustParsePrefix("192.168.0.0/16"):     "RFC 1918: Private-Use",
		netip.MustParsePrefix("192.175.48.0/24"):    "RFC 7534: Direct Delegation AS112 Service",
		netip.MustParsePrefix("198.18.0.0/15"):      "RFC 2544: Benchmarking",
		netip.MustParsePrefix("198.51.100.0/24"):    "RFC 5737: Documentation (TEST-NET-2)",
		netip.MustParsePrefix("203.0.113.0/24"):     "RFC 5737: Documentation (TEST-NET-3)",
		netip.MustParsePrefix("240.0.0.0/4"):        "RFC1112, Section 4: Reserved",
		netip.MustParsePrefix("255.255.255.255/32"): "RFC 8190 & RFC 919, Section 7: Limited Broadcast",
		// 224.0.0.0/4 are multicast addresses as per RFC 3171. They are not
		// present in the IANA registry.
		netip.MustParsePrefix("224.0.0.0/4"): "RFC 3171: Multicast Addresses",
	}
	// Sourced from:
	// https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
	privateV6Prefixes = map[netip.Prefix]string{
		netip.MustParsePrefix("::/128"):            "RFC 4291: Unspecified Address",
		netip.MustParsePrefix("::1/128"):           "RFC 4291: Loopback Address",
		netip.MustParsePrefix("::ffff:0:0/96"):     "RFC 4291: IPv4-mapped Address",
		netip.MustParsePrefix("64:ff9b::/96"):      "RFC 6052: IPv4-IPv6 Translat.",
		netip.MustParsePrefix("64:ff9b:1::/48"):    "RFC 8215: IPv4-IPv6 Translat.",
		netip.MustParsePrefix("100::/64"):          "RFC 6666: Discard-Only Address Block",
		netip.MustParsePrefix("2001::/23"):         "RFC 2928: IETF Protocol Assignments",
		netip.MustParsePrefix("2001::/32"):         "RFC 4380 & RFC 8190: TEREDO",
		netip.MustParsePrefix("2001:1::1/128"):     "RFC 7723: Port Control Protocol Anycast",
		netip.MustParsePrefix("2001:1::2/128"):     "RFC 8155: Traversal Using Relays around NAT Anycast",
		netip.MustParsePrefix("2001:1::3/128"):     "RFC-ietf-dnssd-srp-25: DNS-SD Service Registration Protocol Anycast",
		netip.MustParsePrefix("2001:2::/48"):       "RFC 5180 & RFC Errata 1752: Benchmarking",
		netip.MustParsePrefix("2001:3::/32"):       "RFC 7450: AMT",
		netip.MustParsePrefix("2001:4:112::/48"):   "RFC 7535: AS112-v6",
		netip.MustParsePrefix("2001:10::/28"):      "RFC 4843: Deprecated (previously ORCHID)",
		netip.MustParsePrefix("2001:20::/28"):      "RFC 7343: ORCHIDv2",
		netip.MustParsePrefix("2001:30::/28"):      "RFC 9374: Drone Remote ID Protocol Entity Tags (DETs) Prefix",
		netip.MustParsePrefix("2001:db8::/32"):     "RFC 3849: Documentation",
		netip.MustParsePrefix("2002::/16"):         "RFC 3056: 6to4",
		netip.MustParsePrefix("2620:4f:8000::/48"): "RFC 7534: Direct Delegation AS112 Service",
		netip.MustParsePrefix("3fff::/20"):         "RFC 9637: Documentation",
		netip.MustParsePrefix("5f00::/16"):         "RFC 9602: Segment Routing (SRv6) SIDs",
		netip.MustParsePrefix("fc00::/7"):          "RFC 4193 & RFC 8190: Unique-Local",
		netip.MustParsePrefix("fe80::/10"):         "RFC 4291: Link-Local Unicast",
		// ff00::/8 are multicast addresses as per RFC 4291, Sections 2.4 & 2.7.
		// They are not present in the IANA registry.
		netip.MustParsePrefix("ff00::/8"): "RFC 4291: Multicast Addresses",
	}
)

// IsReservedIP returns whether an IP address is part of a reserved range; the
// range's name, if so; or an error.
func IsReservedIP(ip net.IP) (bool, string, error) {
	netIP, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false, "", errIPInvalid
	}
	// 4in6 would be unexpected and unwelcome. It must be squashed.
	netIP = netIP.Unmap()

	var reservedPrefixes map[netip.Prefix]string
	if netIP.Is4() {
		reservedPrefixes = privateV4Prefixes
	} else {
		reservedPrefixes = privateV6Prefixes
	}

	for net, name := range reservedPrefixes {
		if net.Contains(netIP) {
			return true, name, nil
		}
	}

	return false, "", nil
}

// IsNonLoopbackReservedIP wraps IsReservedIP but excludes loopback ranges.
//
// This should *only* be called from tests (unit or integration).
func IsNonLoopbackReservedIP(ip net.IP) (bool, string, error) {
	reserved, name, err := IsReservedIP(ip)
	if reserved && strings.Contains(name, "Loopback") {
		return false, "", nil
	}
	return reserved, name, err
}
