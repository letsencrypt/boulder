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
	UsageRequestsPerIPv4Address Name = iota
	InfoRequestsPerIPv4Address
	NewRegistrationsPerIPv4Address
	NewRegistrationsPerIPv6Range
	NewOrdersPerAccount
	FailedAuthorizationsPerAccount
	CertificatesPerRegisteredDomain
	CertificatesPerFQDNSet
)

// nameToString is a map of Name values to string names.
var nameToString = map[Name]string{
	UsageRequestsPerIPv4Address:     "UsageRequestsPerIPv4Address",
	InfoRequestsPerIPv4Address:      "InfoRequestsPerIPv4Address",
	NewRegistrationsPerIPv4Address:  "NewRegistrationsPerIPv4Address",
	NewRegistrationsPerIPv6Range:    "NewRegistrationsPerIPv6Range",
	NewOrdersPerAccount:             "NewOrdersPerAccount",
	FailedAuthorizationsPerAccount:  "FailedAuthorizationsPerAccount",
	CertificatesPerRegisteredDomain: "CertificatesPerRegisteredDomain",
	CertificatesPerFQDNSet:          "CertificatesPerFQDNSet",
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

func ipv4AddrNameId(name Name) bool {
	n, ok := nameToString[name]
	if !ok {
		return false
	}
	if strings.Contains(n, "IPv4Address") {
		return true
	}
	return false
}

// ipv6RangeNameId returns true if the name is an IPv6Range rate limit name.
func ipv6RangeNameId(name Name) bool {
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
