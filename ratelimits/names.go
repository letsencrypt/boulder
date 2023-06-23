package ratelimits

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Name is an enumeration of all rate limit names. It is used to intern rate
// limit names as strings and to provide a type-safe way to refer to rate
// limits.
//
// IMPORTANT: If you add a new limit Name, you MUST add it to the 'nameToString'
// mapping and idValidForName function below.
type Name int

const (
	// UsageRequestsPerIPv4Address uses bucket key 'enum:ipv4address'.
	UsageRequestsPerIPv4Address Name = iota

	// InfoRequestsPerIPv4Address uses bucket key 'enum:ipv4address'.
	InfoRequestsPerIPv4Address

	// NewRegistrationsPerIPv4Address uses bucket key 'enum:ipv4address'.
	NewRegistrationsPerIPv4Address

	// NewRegistrationsPerIPv6Range uses bucket key 'enum:ipv6rangeCIDR'. The
	// range itself must be a /48.
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
	InfoRequestsPerIPv4Address:       "InfoRequestsPerIPv4Address",
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
	_, net, err := net.ParseCIDR(id)
	if err != nil {
		return fmt.Errorf(
			"invalid CIDR, %q must be an IPv6 CIDR range", id)
	}
	if net.IP.To4() != nil {
		return fmt.Errorf(
			"invalid CIDR, %q must be an IPv6 range, not IPv4", id)
	}
	ones, _ := net.Mask.Size()
	if ones != 48 {
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

var domainRegExp = regexp.MustCompile(`^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$`)

// validateRegIdDomain validates that the provided string is formatted
// 'regId:domain'.
func validateRegIdDomain(id string) error {
	p := strings.SplitN(id, ":", 2)
	if len(p) != 2 {
		return fmt.Errorf("invalid regId:domain, %q must be in the form 'regId:domain'", id)
	}
	err := validateRegId(p[0])
	if err != nil {
		return err
	}
	if !domainRegExp.MatchString(p[1]) {
		return fmt.Errorf("invalid regId:domain, %q must be a domain", id)

	}
	return nil
}

// validateRegIdFQDNSet validates that the provided string is formatted
// 'regId:fqdnSet', where fqdnSet is a comma separated list of FQDNs.
func validateRegIdFQDNSet(id string) error {
	p := strings.SplitN(id, ":", 2)
	if len(p) != 2 {
		return fmt.Errorf("invalid 'regId:fqdnSet', %q must be in the form 'regId:fqdn,...'", id)
	}
	err := validateRegId(p[0])
	if err != nil {
		return err
	}
	fqdns := strings.Split(p[1], ",")
	if len(fqdns) == 0 {
		return fmt.Errorf("invalid 'regId:fqdnSet', %q must be a comma separated list of FQDNs", p[1])
	}
	for _, fqdn := range fqdns {
		if !domainRegExp.MatchString(fqdn) {
			return fmt.Errorf("invalid 'regId:fqdnSet', %q must be a comma separated list of FQDNs", p[1])
		}
	}
	return nil
}

func validateIdForName(name Name, id string) error {
	switch name {
	case UsageRequestsPerIPv4Address, InfoRequestsPerIPv4Address, NewRegistrationsPerIPv4Address:
		// 'enum:ipv4address'
		return validIPv4Address(id)

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

// nameToIntString converts the integer value of the Name enumeration to its
// string representation.
func nameToIntString(s Name) string {
	return strconv.Itoa(int(s))
}

// bucketKey returns the key used to store a rate limit bucket.
func bucketKey(name Name, id string) string {
	return nameToIntString(name) + ":" + id
}
