package web

import (
	"net/http"
	"net/url"
	"path"
)

// RelativeEndpoint constructs a URL using the scheme and host inferred from
// request, and a path composed of basePath plus any additional path segments.
// All trailing slashes will be removed from the resulting URL.
//
// basePath is an absolute path as defined in RFC 3986 section 3.3 and thus
// should begin with "/" (e.g. "/acme/acct/"). Segments are additional path
// segments to be appended to basePath and should not contain slashes.
func RelativeEndpoint(request *http.Request, basePath string, segments ...string) string {
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

	paths := []string{basePath}
	paths = append(paths, segments...)
	endpoint := path.Join(paths...)

	resultUrl := url.URL{Scheme: proto, Host: host, Path: endpoint}
	result = resultUrl.String()

	return result
}
