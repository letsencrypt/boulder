package iana

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"sync"

	_ "embed"
)

type ReservedPrefix struct {
	// AddressFamily values are defined in:
	// https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
	AddressFamily uint16
	// The other fields are defined in:
	// https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
	// https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
	AddressBlock netip.Prefix
	Name         string
	RFC          string
	// AllocationDate     time.Time
	// TerminationDate    time.Time
	// Source             bool
	// Destination        bool
	// Forwardable        bool
	// GloballyReachable  bool
	// ReservedByProtocol bool
}

var (
	reservedPrefixes   []ReservedPrefix
	reservedPrefixesMu sync.RWMutex

	// https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
	//go:embed data/iana-ipv4-special-registry-1.csv
	ipv4Registry []byte
	// https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
	//go:embed data/iana-ipv6-special-registry-1.csv
	ipv6Registry []byte
)

// loadReservedPrefixes parses and loads the embedded IANA special-purpose
// address registry CSV files for all address families, returning an error if
// any one fails.
func loadReservedPrefixes() error {
	reservedPrefixesMu.Lock()
	defer reservedPrefixesMu.Unlock()

	if len(reservedPrefixes) > 0 {
		// Another thread has already loaded the data.
		return nil
	}

	ipv4Prefixes, err := parseReservedPrefixFile(ipv4Registry, 1)
	if err != nil {
		return err
	}
	reservedPrefixes = ipv4Prefixes

	ipv6Prefixes, err := parseReservedPrefixFile(ipv6Registry, 2)
	if err != nil {
		return err
	}
	reservedPrefixes = append(reservedPrefixes, ipv6Prefixes...)

	// Add multicast addresses, which aren't in the IANA registries.
	//
	// TODO(#8237): Move these entries to IP address blocklists once they're
	// implemented.
	reservedPrefixes = append(reservedPrefixes,
		ReservedPrefix{
			AddressFamily: 1, // IPv4
			AddressBlock:  netip.MustParsePrefix("224.0.0.0/4"),
			Name:          "Multicast Addresses",
			RFC:           "RFC3171",
		},
		ReservedPrefix{
			AddressFamily: 2, // IPv6
			AddressBlock:  netip.MustParsePrefix("ff00::/8"),
			Name:          "Multicast Addresses",
			RFC:           "RFC4291",
		},
	)

	return nil
}

// parseReservedPrefixFile parses and returns the IANA special-purpose address
// registry CSV data for a single address family, or returns an error if parsing
// fails.
func parseReservedPrefixFile(registryData []byte, addressFamily uint16) ([]ReservedPrefix, error) {
	if addressFamily != 1 && addressFamily != 2 {
		return nil, fmt.Errorf("failed to parse reserved address registry: invalid address family %d", addressFamily)
	}
	if registryData == nil {
		return nil, fmt.Errorf("failed to parse reserved address registry %d: empty", addressFamily)
	}

	reader := csv.NewReader(bytes.NewReader(registryData))

	// Parse the header row.
	record, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to parse reserved address registry %d header: %w", addressFamily, err)
	}
	if record[0] != "Address Block" || record[1] != "Name" || record[2] != "RFC" {
		return nil, fmt.Errorf("failed to parse reserved address registry %d header: must begin with \"Address Block\", \"Name\" and \"RFC\"", addressFamily)
	}

	// Define regexps we'll use to clean up poorly formatted registry entries.
	//
	// 2+ sequential whitespace characters. The csv package takes care of
	// newlines automatically.
	whitespacesRE := regexp.MustCompile(`\s{2,}`)
	// Footnotes at the end, like `[2]`.
	footnotesRE := regexp.MustCompile(`\[\d+\]$`)

	// Parse the records.
	var prefixes []ReservedPrefix
	for {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			// Finished parsing the file.
			if len(prefixes) < 1 {
				return nil, fmt.Errorf("failed to parse reserved address registry %d: no rows after header", addressFamily)
			}
			break
		} else if err != nil {
			return nil, err
		}

		// Remove any footnotes, then handle each comma-separated prefix.
		for _, prefixStr := range strings.Split(footnotesRE.ReplaceAllLiteralString(row[0], ""), ",") {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(prefixStr))
			if err != nil {
				return nil, fmt.Errorf("failed to parse reserved address registry %d: couldn't parse entry %q as an IP address prefix: %s", addressFamily, prefixStr, err)
			}

			prefixes = append(prefixes, ReservedPrefix{
				AddressFamily: addressFamily,
				AddressBlock:  prefix,
				Name:          row[1],
				// Replace any whitespace sequences with a single space.
				RFC: whitespacesRE.ReplaceAllLiteralString(row[2], " "),
			})
		}
	}

	return prefixes, nil
}

// IsReservedAddr returns an error if an IP address is part of a reserved range.
func IsReservedAddr(ip netip.Addr) error {
	if len(reservedPrefixes) < 1 {
		err := loadReservedPrefixes()
		if err != nil {
			return err
		}
	}

	reservedPrefixesMu.RLock()
	defer reservedPrefixesMu.RUnlock()

	for _, rpx := range reservedPrefixes {
		if rpx.AddressBlock.Contains(ip) {
			return fmt.Errorf("IP address is in a reserved address block: %s: %s", rpx.RFC, rpx.Name)
		}
	}

	return nil
}

// IsReservedPrefix returns an error if an IP address prefix overlaps with a
// reserved range.
func IsReservedPrefix(prefix netip.Prefix) error {
	if len(reservedPrefixes) < 1 {
		err := loadReservedPrefixes()
		if err != nil {
			return err
		}
	}

	reservedPrefixesMu.RLock()
	defer reservedPrefixesMu.RUnlock()

	for _, rpx := range reservedPrefixes {
		if rpx.AddressBlock.Overlaps(prefix) {
			return fmt.Errorf("IP address is in a reserved address block: %s: %s", rpx.RFC, rpx.Name)
		}
	}

	return nil
}
