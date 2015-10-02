package core

import "strings"

// ReverseName takes a domain name and returns a label-wise reversed version of
// it. Example:
// ReverseName("www.example.com") == "com.example.www"
// This is useful for storing domain names in a DB such than subdomains of the
// same parent domain are near each other.
func ReverseName(domain string) string {
	labels := strings.Split(domain, ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, ".")
}
