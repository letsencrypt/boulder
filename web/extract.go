package web

import (
	"net"
	"net/http"
	"net/netip"
)

// ExtractRequesterIP extracts the IP address of the requester from the HTTP
// request. It first checks the "X-Real-IP" header, and if that is not set, it
// falls back to the RemoteAddr field of the request. An error is returned if
// the IP address cannot be determined.
func ExtractRequesterIP(req *http.Request) (netip.Addr, error) {
	ip, err := netip.ParseAddr(req.Header.Get("X-Real-IP"))
	if err == nil {
		return ip, nil
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(host)
}
