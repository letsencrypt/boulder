package ratelimits

import "strconv"

// Name is a rate limit name.
type Name int

const (
	// Each unique IPv4 address can make 20 requests, per second, to /new-nonce,
	// /new-account, /new-order, or /revoke-cert
	UsageRequestsPerIPv4Address Name = iota

	// Each unique IPv4 address can make 40 requests, per second, to
	// /directory and /acme.
	InfoRequestsPerIPv4Address

	// Each IPv4 address can create 10 accounts every 3 hours.
	NewRegistrationsPerIPv4Address

	// Each /48 IPv6 range can create 500 accounts every 3 hours.
	NewRegistrationsPerIPv6Range

	// Each account can create 300 orders per 3 hour period.
	NewOrdersPerAccount

	// Each account can fail 5 authorizations (validations) per hostname per
	// hour.
	FailedAuthorizationsPerAccount

	// 50 certificates per domain name every 7 days.
	CertificatesPerRegisteredDomain

	// 5 certificates per unique set of names every 7 days.
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
