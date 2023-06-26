package ratelimits

import (
	"fmt"
	"net"
	"strconv"
)

// Name is an enumeration of all rate limit names. It is used to intern rate
// limit names as strings and to provide a type-safe way to refer to rate
// limits.
//
// IMPORTANT: If you add a new limit Name, you MUST add it to the 'nameToString'
// mapping and idValidForName function below.
type Name int

const (
	// UsageRequestsPerIPv4Address uses bucket key 'enum:ipv4address'. Usage
	// related paths are: new-nonce, new-account, new-order, or revoke-cert.
	UsageRequestsPerIPv4Address Name = iota

	// UsageRequestsPerIPv6Range uses bucket key 'enum:ipv6rangeCIDR'. The
	// address range must be a /48. Usage related paths are: new-nonce,
	// new-account, new-order, or revoke-cert.
	UsageRequestsPerIPv6Range

	// InfoRequestsPerIPv4Address uses bucket key 'enum:ipv4address'. Info
	// related paths are: directory and acme.
	InfoRequestsPerIPv4Address

	// InfoRequestsPerIPv6Range uses bucket key 'enum:ipv6rangeCIDR'. The
	// address range must be a /48. Info related paths are: directory and acme.
	InfoRequestsPerIPv6Range

	// NewRegistrationsPerIPv4Address uses bucket key 'enum:ipv4address'.
	NewRegistrationsPerIPv4Address

	// NewRegistrationsPerIPv6Range uses bucket key 'enum:ipv6rangeCIDR'. The
	// address range must be a /48.
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

// nameToString is a map of Name values to string names.
var nameToString = map[Name]string{
	UsageRequestsPerIPv4Address:      "UsageRequestsPerIPv4Address",
	UsageRequestsPerIPv6Range:        "UsageRequestsPerIPv6Range",
	InfoRequestsPerIPv4Address:       "InfoRequestsPerIPv4Address",
	InfoRequestsPerIPv6Range:         "InfoRequestsPerIPv6Range",
	NewRegistrationsPerIPv4Address:   "NewRegistrationsPerIPv4Address",
	NewRegistrationsPerIPv6Range:     "NewRegistrationsPerIPv6Range",
	NewOrdersPerAccount:              "NewOrdersPerAccount",
	FailedAuthorizationsPerAccount:   "FailedAuthorizationsPerAccount",
	CertificatesPerDomainPerAccount:  "CertificatesPerDomainPerAccount",
	CertificatesPerFQDNSetPerAccount: "CertificatesPerFQDNSetPerAccount",
}

// validIPv4Address validates that the provided string is a valid IPv4 address.
func validIPv4Address(id string) error {
	ip := net.ParseIP(id)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf(
			"invalid address, %q must be IPv4 address", id)
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

func validateIdForName(name Name, id string) error {
	switch name {
	case UsageRequestsPerIPv4Address, InfoRequestsPerIPv4Address:
		// 'enum:ipv4address'
		return validIPv4Address(id)

	case UsageRequestsPerIPv6Range, InfoRequestsPerIPv6Range:
		// 'enum:ipv6rangeCIDR'
		return validIPv6RangeCIDR(id)

	case NewOrdersPerAccount:
		// 'enum:regId'
		return validateRegId(id)

	case NewRegistrationsPerIPv4Address,
		NewRegistrationsPerIPv6Range,
		FailedAuthorizationsPerAccount,
		CertificatesPerDomainPerAccount,
		CertificatesPerFQDNSetPerAccount:
		return fmt.Errorf("overrides are not supported for limit %q", name)

	default:
		// This should never happen.
		return fmt.Errorf("invalid limit enum %q", name)
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
