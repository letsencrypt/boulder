package ratelimits

import "strconv"

// Name is a rate limit name.
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

// stringToName is a map of string names to Name values.
//
// IMPORTANT: If you add a new rate limit Name, you must add it to this map.
var stringToName = map[string]Name{
	"UsageRequestsPerIPv4Address":     UsageRequestsPerIPv4Address,
	"InfoRequestsPerIPv4Address":      InfoRequestsPerIPv4Address,
	"NewRegistrationsPerIPv4Address":  NewRegistrationsPerIPv4Address,
	"NewRegistrationsPerIPv6Range":    NewRegistrationsPerIPv6Range,
	"NewOrdersPerAccount":             NewOrdersPerAccount,
	"FailedAuthorizationsPerAccount":  FailedAuthorizationsPerAccount,
	"CertificatesPerRegisteredDomain": CertificatesPerRegisteredDomain,
	"CertificatesPerFQDNSet":          CertificatesPerFQDNSet,
}

// limitNames is a list of all rate limit names.
var limitNames = func() []string {
	var names []string
	for name := range stringToName {
		names = append(names, name)
	}
	return names
}()

func nameToIntString(s Name) string {
	return strconv.Itoa(int(s))
}

func bucketKey(name Name, id string) string {
	return nameToIntString(name) + ":" + id
}

func overrideKey(name Name, id string) string {
	return bucketKey(name, id)
}
