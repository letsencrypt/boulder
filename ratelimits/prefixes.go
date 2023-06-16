package ratelimits

import "strconv"

type Prefix int

const (
	// Each unique IPv4 address can make 20 requests, per second, to /new-nonce,
	// /new-account, /new-order, or /revoke-cert
	UsageRequestsPerIPv4Address Prefix = iota

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

var prefixToString = map[Prefix]string{
	UsageRequestsPerIPv4Address:     "UsageRequestsPerIPv4Address",
	InfoRequestsPerIPv4Address:      "InfoRequestsPerIPv4Address",
	NewRegistrationsPerIPv4Address:  "NewRegistrationsPerIPv4Address",
	NewRegistrationsPerIPv6Range:    "NewRegistrationsPerIPv6Range",
	NewOrdersPerAccount:             "NewOrdersPerAccount",
	FailedAuthorizationsPerAccount:  "FailedAuthorizationsPerAccount",
	CertificatesPerRegisteredDomain: "CertificatesPerRegisteredDomain",
	CertificatesPerFQDNSet:          "CertificatesPerFQDNSet",
}

func isIntPrefix(s int) bool {
	_, exists := prefixToString[Prefix(s)]
	return exists
}

func prefixToIntString(s Prefix) string {
	return strconv.Itoa(int(s))
}

func overrideKey(prefix Prefix, id string) string {
	return bucketKey(prefix, id)
}

func bucketKey(prefix Prefix, id string) string {
	return prefixToIntString(prefix) + ":" + id
}
