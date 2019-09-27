package web

import (
	"net/http"
	"net/url"
	"strings"
)

// RelativeEndpoint takes a path component of URL and constructs a new URL using
// the host and port from the request combined the provided path.
func RelativeEndpoint(request *http.Request, endpoint string) string {
	var result string
	proto := "http"
	host := request.Host

	// If the request was received via TLS, use `https://` for the protocol
	if request.TLS != nil {
		proto = "https"
	}

	// If a client sends a HTTP Host header that includes the default port
	// for a scheme then we strip the port out of the host and return the
	// standards compliant host instead. This is mainly done to prevent
	// returning a directory to the user that includes the port, which they
	// would then use in the 'url' JWS signature header.
	if proto == "https" && strings.HasSuffix(host, ":443") {
		host = strings.TrimSuffix(host, ":443")
	} else if proto == "http" && strings.HasSuffix(host, ":80") {
		host = strings.TrimSuffix(host, ":80")
	}

	// Allow upstream proxies  to specify the forwarded protocol. Allow this value
	// to override our own guess.
	if specifiedProto := request.Header.Get("X-Forwarded-Proto"); specifiedProto != "" {
		proto = specifiedProto
	}

	// Default to "localhost" when no request.Host is provided. Otherwise requests
	// with an empty `Host` produce results like `http:///acme/new-authz`
	if request.Host == "" {
		host = "localhost"
	}

	resultUrl := url.URL{Scheme: proto, Host: host, Path: endpoint}
	result = resultUrl.String()

	return result
}
