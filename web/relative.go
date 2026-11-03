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
	proto := RequestProto(request)
	host := RequestHost(request)

	// Default to "localhost" when no request.Host is provided. Otherwise requests
	// with an empty `Host` produce results like `http:///acme/new-authz`
	if request.Host == "" {
		host = "localhost"
	}

	// path.Join will clean the resulting path, removing any trailing slashes.
	endpoint := path.Join(append([]string{basePath}, segments...)...)

	resultUrl := url.URL{Scheme: proto, Host: host, Path: endpoint}
	result = resultUrl.String()

	return result
}

// RequestHost returns the host the client addressed. It is request.Host unless
// an upstream proxy set X-Forwarded-Host, which then takes precedence.
func RequestHost(request *http.Request) string {
	specifiedHost := request.Header.Get("X-Forwarded-Host")
	if specifiedHost != "" {
		return specifiedHost
	}
	return request.Host
}

// RequestProto returns "http" for HTTP requests and "https" for HTTPS requests.
// X-Forwarded-Proto, when set by an upstream proxy, overrides that choice.
func RequestProto(request *http.Request) string {
	proto := "http"
	if request.TLS != nil {
		proto = "https"
	}

	specifiedProto := request.Header.Get("X-Forwarded-Proto")
	if specifiedProto != "" {
		proto = specifiedProto
	}
	return proto
}
