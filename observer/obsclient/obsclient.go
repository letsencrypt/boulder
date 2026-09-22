// package obsdialer contains a custom dialer for use in observers.
package obsclient

import (
	"crypto/tls"
	"net"
	"net/http"
)

var secureClient = newClient(false)
var insecureClient = newClient(true)

// Client returns a shared *http.Client, with the appropriate TLS configuration,
// shared across all probers.
func Client(insecure bool) *http.Client {
	if insecure {
		return insecureClient
	}
	return secureClient
}

func newClient(insecure bool) *http.Client {
	// Use the default transport, because it comes with useful defaults that are
	// not just the http.Transport zero-values.
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = Dialer().DialContext
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecure}

	return &http.Client{Transport: t}
}

// Dialer returns a custom dialer for use in probers. It disables IPv6-to-IPv4
// fallback so we don't mask failures of IPv6 connectivity.
func Dialer() *net.Dialer {
	return &net.Dialer{
		FallbackDelay: -1, // Disable IPv6-to-IPv4 fallback
	}
}
