package web

import (
	"net/http"
	"net/url"
	"path"
)

// RelativeEndpoint takes a path component of URL and constructs a new URL using
// the host and port from the request combined the provided basePath and any
// additionalPaths if provided. If only a basePath is provided with no
// additionalPaths and the basePath has a trailing slash, the trailing
// slash will be retained.
func RelativeEndpoint(request *http.Request, basePath string, additionalPaths ...string) string {
	var result string
	proto := "http"
	host := request.Host

	// If the request was received via TLS, use `https://` for the protocol
	if request.TLS != nil {
		proto = "https"
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

	endpoint := basePath
	// Checking for additionalPaths is vital because path.Join runs path.Clean
	// and removes trailing slashes but there are scenarios such as in
	// WebFrontEndImpl.acctIDFromURL where the basePath is only
	// provided and the trailing slash needs to be kept
	if len(additionalPaths) > 0 {
		paths := []string{basePath}
		paths = append(paths, additionalPaths...)
		endpoint = path.Join(paths...)
	}

	resultUrl := url.URL{Scheme: proto, Host: host, Path: endpoint}
	result = resultUrl.String()

	return result
}
