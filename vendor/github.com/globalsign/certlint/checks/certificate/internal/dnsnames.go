package internal

import (
	"net"
	"strings"

	psl "golang.org/x/net/publicsuffix"
)

// All official domain suffixes are registered by icann, but because some
// subdomains are not only check against the last part of the fqdn.
func checkInternalName(fqdn string) bool {
	if ip := net.ParseIP(fqdn); ip != nil {
		return checkInternalIP(ip)
	}

	suffix := strings.Split(strings.ToLower(fqdn), ".")
	_, icann := psl.PublicSuffix(suffix[len(suffix)-1])
	if icann {
		return false
	}
	return true
}
