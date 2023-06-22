package ratelimits

import (
	"strconv"
	"strings"
)

// Name is an enumeration of all rate limit names. It is used to intern rate
// limit names as strings and to provide a type-safe way to refer to rate
// limits.
//
// IMPORTANT: If you add a new limit Name, you MUST add it to the 'nameToString'
// mapping. Also, new IPv4Address and IPv6Range rate limit names MUST contain
// the string "IPv4Address" and "IPv6Range", respectively.
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

	// CertificatesPerNamePerAccount uses bucket key 'enum:regId:name', where
	// name is the a name in a certificate issued to the account matching regId.
	CertificatesPerNamePerAccount

	// CertificatesPerNameSetPerAccount uses bucket key 'enum:regId:nameSet',
	// where nameSet is a set of names in a certificate issued to the account
	// matching regId.
	CertificatesPerNameSetPerAccount
)

// nameToString is a map of Name values to string names.
var nameToString = map[Name]string{
	UsageRequestsPerIPv4Address:      "UsageRequestsPerIPv4Address",
	InfoRequestsPerIPv4Address:       "InfoRequestsPerIPv4Address",
	NewRegistrationsPerIPv4Address:   "NewRegistrationsPerIPv4Address",
	NewRegistrationsPerIPv6Range:     "NewRegistrationsPerIPv6Range",
	NewOrdersPerAccount:              "NewOrdersPerAccount",
	FailedAuthorizationsPerAccount:   "FailedAuthorizationsPerAccount",
	CertificatesPerNamePerAccount:    "CertificatesPerNameAccount",
	CertificatesPerNameSetPerAccount: "CertificatesPerNameSetAccount",
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

func idIsIPv4Addr(name Name) bool {
	n, ok := nameToString[name]
	if !ok {
		return false
	}
	if strings.Contains(n, "IPv4Address") {
		return true
	}
	return false
}

// idIsIPv6Range returns true if the name is an IPv6Range rate limit name.
func idIsIPv6Range(name Name) bool {
	n, ok := nameToString[name]
	if !ok {
		return false
	}
	if strings.Contains(n, "IPv6Range") {
		return true
	}
	return false
}

// nameToIntString converts the integer value of the Name enumeration to its
// string representation.
func nameToIntString(s Name) string {
	return strconv.Itoa(int(s))
}

// bucketKey returns the key used to store a rate limit bucket.
func bucketKey(name Name, id string) string {
	return nameToIntString(name) + ":" + id
}
