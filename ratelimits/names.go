package ratelimits

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/letsencrypt/boulder/policy"
)

// Name is an enumeration of all rate limit names. It is used to intern rate
// limit names as strings and to provide a type-safe way to refer to rate
// limits.
//
// IMPORTANT: If you add a new limit Name, you MUST add it to the 'nameToString'
// mapping and idValidForName function below.
type Name int

const (
	// Unknown is the zero value of Name and is used to indicate an unknown
	// limit name.
	Unknown Name = iota

	// NewRegistrationsPerIPAddress uses bucket key 'enum:ipAddress'.
	NewRegistrationsPerIPAddress

	// NewRegistrationsPerIPv6Range uses bucket key 'enum:ipv6rangeCIDR'. The
	// address range must be a /48. RFC 3177, which was published in 2001,
	// advised operators to allocate a /48 block of IPv6 addresses for most end
	// sites. RFC 6177, which was published in 2011 and obsoletes RFC 3177,
	// advises allocating a smaller /56 block. We've chosen to use the larger
	// /48 block for our IPv6 rate limiting. See:
	//   1. https://tools.ietf.org/html/rfc3177#section-3
	//   2. https://datatracker.ietf.org/doc/html/rfc6177#section-2
	NewRegistrationsPerIPv6Range

	// NewOrdersPerAccount uses bucket key 'enum:regId'.
	NewOrdersPerAccount

	// FailedAuthorizationsPerAccount uses bucket key 'enum:regId', where regId
	// is the registration id of the account.
	FailedAuthorizationsPerAccount

	// CertificatesPerDomainPerAccount uses bucket key 'enum:regId:domain',
	// where name is the a name in a certificate issued to the account matching
	// regId.
	CertificatesPerDomainPerAccount

	// CertificatesPerFQDNSetPerAccount uses bucket key 'enum:regId:fqdnSet',
	// where nameSet is a set of names in a certificate issued to the account
	// matching regId.
	CertificatesPerFQDNSetPerAccount
)

// isValid returns true if the Name is a valid rate limit name.
func (n Name) isValid() bool {
	return n > Unknown && n < Name(len(nameToString))
}

// String returns the string representation of the Name. It allows Name to
// satisfy the fmt.Stringer interface.
func (n Name) String() string {
	if !n.isValid() {
		return nameToString[Unknown]
	}
	return nameToString[n]
}

// nameToString is a map of Name values to string names.
var nameToString = map[Name]string{
	Unknown:                          "Unknown",
	NewRegistrationsPerIPAddress:     "NewRegistrationsPerIPAddress",
	NewRegistrationsPerIPv6Range:     "NewRegistrationsPerIPv6Range",
	NewOrdersPerAccount:              "NewOrdersPerAccount",
	FailedAuthorizationsPerAccount:   "FailedAuthorizationsPerAccount",
	CertificatesPerDomainPerAccount:  "CertificatesPerDomainPerAccount",
	CertificatesPerFQDNSetPerAccount: "CertificatesPerFQDNSetPerAccount",
}

// validIPAddress validates that the provided string is a valid IP address.
func validIPAddress(id string) error {
	ip := net.ParseIP(id)
	if ip == nil {
		return fmt.Errorf("invalid IP address, %q must be an IP address", id)
	}
	return nil
}

// validIPv6RangeCIDR validates that the provided string is formatted is an IPv6
// CIDR range with a /48 mask.
func validIPv6RangeCIDR(id string) error {
	_, ipNet, err := net.ParseCIDR(id)
	if err != nil {
		return fmt.Errorf(
			"invalid CIDR, %q must be an IPv6 CIDR range", id)
	}
	ones, _ := ipNet.Mask.Size()
	if ones != 48 {
		// This also catches the case where the range is an IPv4 CIDR, since an
		// IPv4 CIDR can't have a /48 subnet mask - the maximum is /32.
		return fmt.Errorf(
			"invalid CIDR, %q must be /48", id)
	}
	return nil
}

// validateRegId validates that the provided string is a valid ACME regId.
func validateRegId(id string) error {
	_, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid regId, %q must be an ACME registration Id", id)
	}
	return nil
}

// validateRegIdDomain validates that the provided string is formatted
// 'regId:domain', where regId is an ACME registration Id and domain is a single
// domain name.
func validateRegIdDomain(id string) error {
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf(
			"invalid regId:domain, %q must be formatted 'regId:domain'", id)
	}
	if validateRegId(parts[0]) != nil {
		return fmt.Errorf(
			"invalid regId, %q must be formatted 'regId:domain'", id)
	}
	if policy.ValidDomain(parts[1]) != nil {
		return fmt.Errorf(
			"invalid domain, %q must be formatted 'regId:domain'", id)
	}
	return nil
}

// validateRegIdFQDNSet validates that the provided string is formatted
// 'regId:fqdnSet', where regId is an ACME registration Id and fqdnSet is a
// comma-separated list of domain names.
func validateRegIdFQDNSet(id string) error {
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf(
			"invalid regId:fqdnSet, %q must be formatted 'regId:fqdnSet'", id)
	}
	if validateRegId(parts[0]) != nil {
		return fmt.Errorf(
			"invalid regId, %q must be formatted 'regId:fqdnSet'", id)
	}
	domains := strings.Split(parts[1], ",")
	if len(domains) == 0 {
		return fmt.Errorf(
			"invalid fqdnSet, %q must be formatted 'regId:fqdnSet'", id)
	}
	for _, domain := range domains {
		if policy.ValidDomain(domain) != nil {
			return fmt.Errorf(
				"invalid domain, %q must be formatted 'regId:fqdnSet'", id)
		}
	}
	return nil
}

func validateIdForName(name Name, id string) error {
	switch name {
	case NewRegistrationsPerIPAddress:
		// 'enum:ipaddress'
		return validIPAddress(id)

	case NewRegistrationsPerIPv6Range:
		// 'enum:ipv6rangeCIDR'
		return validIPv6RangeCIDR(id)

	case NewOrdersPerAccount, FailedAuthorizationsPerAccount:
		// 'enum:regId'
		return validateRegId(id)

	case CertificatesPerDomainPerAccount:
		// 'enum:regId:domain'
		return validateRegIdDomain(id)

	case CertificatesPerFQDNSetPerAccount:
		// 'enum:regId:fqdnSet'
		return validateRegIdFQDNSet(id)

	case Unknown:
		fallthrough

	default:
		// This should never happen.
		return fmt.Errorf("unknown limit enum %q", name)
	}
}

// stringToName is a map of string names to Name values.
var stringToName = func() map[string]Name {
	m := make(map[string]Name, len(nameToString))
	for k, v := range nameToString {
		m[v] = k
	}
	return m
}()

// limitNames is a slice of all rate limit names.
var limitNames = func() []string {
	names := make([]string, len(nameToString))
	for _, v := range nameToString {
		names = append(names, v)
	}
	return names
}()

// nameToEnumString converts the integer value of the Name enumeration to its
// string representation.
func nameToEnumString(s Name) string {
	return strconv.Itoa(int(s))
}

// bucketKey returns the key used to store a rate limit bucket.
func bucketKey(name Name, id string) string {
	return nameToEnumString(name) + ":" + id
}
