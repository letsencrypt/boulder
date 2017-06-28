// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package safebrowsing

// The logic below deals with extracting patterns from a URL.
// Patterns are all the possible host-suffix and path-prefix fragments for
// the input URL.
//
// From example, the patterns for the given URL are the following:
//	input: "http://a.b.c/1/2.html?param=1/2"
//	patterns: [
//		"a.b.c/1/2.html?param=1/2",
//		"a.b.c/1/2.html",
//		"a.b.c/1/",
//		"a.b.c/",
//		"b.c/1/2.html?param=1/2",
//		"b.c/1/2.html",
//		"b.c/1/",
//		"b.c/"
//	]
//
// The process that Safe Browsing uses predates Chrome and many RFC standards
// and is partly based on how legacy browsers typically parse URLs. Thus, we
// parse URLs in a way that is not strictly standards compliant.
//
// The parsing policy is documented here:
//	https://developers.google.com/safe-browsing/

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

var (
	dotsRegexp          = regexp.MustCompile("[.]+")
	portRegexp          = regexp.MustCompile(`:\d+$`)
	possibleIPRegexp    = regexp.MustCompile(`^(?i)((?:0x[0-9a-f]+|[0-9\.])+)$`)
	trailingSpaceRegexp = regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) `)
)

// generateHashes returns a set of full hashes for all patterns in the URL.
func generateHashes(url string) (map[hashPrefix]string, error) {
	patterns, err := generatePatterns(url)
	if err != nil {
		return nil, err
	}

	hashes := make(map[hashPrefix]string)
	for _, p := range patterns {
		hashes[hashFromPattern(p)] = p
	}
	return hashes, nil
}

// generatePatterns returns all possible host-suffix and path-prefix patterns
// for the input URL.
func generatePatterns(url string) ([]string, error) {
	hosts, err := generateLookupHosts(url)
	if err != nil {
		return nil, err
	}
	paths, err := generateLookupPaths(url)
	if err != nil {
		return nil, err
	}
	var patterns []string
	for _, h := range hosts {
		for _, p := range paths {
			patterns = append(patterns, h+p)
		}
	}
	return patterns, nil
}

// isHex reports whether c is a hexadecimal character.
func isHex(c byte) bool {
	switch {
	case '0' <= c && c <= '9':
		return true
	case 'a' <= c && c <= 'f':
		return true
	case 'A' <= c && c <= 'F':
		return true
	}
	return false
}

// unhex converts a hexadecimal character to byte value in 0..15, inclusive.
func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

// isUnicode reports whether s is a Unicode string.
func isUnicode(s string) bool {
	for _, c := range []byte(s) {
		// For legacy reasons, 0x80 is not considered a Unicode character.
		if c > 0x80 {
			return true
		}
	}
	return false
}

// split splits the string s around the delimiter c.
//
// Let string s be of the form:
//	"%s%s%s" % (t, c, u)
//
// Then split returns (t, u) if cutc is set, otherwise, it returns (t, c+u).
// If c does not exist in s, then (s, "") is returned.
func split(s string, c string, cutc bool) (string, string) {
	i := strings.Index(s, c)
	if i < 0 {
		return s, ""
	}
	if cutc {
		return s[:i], s[i+len(c):]
	}
	return s[:i], s[i:]
}

// escape returns the percent-encoded form of the string s.
func escape(s string) string {
	var b bytes.Buffer
	for _, c := range []byte(s) {
		if c < 0x20 || c >= 0x7f || c == ' ' || c == '#' || c == '%' {
			b.WriteString(fmt.Sprintf("%%%02x", c))
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// unescape returns the decoded form of a percent-encoded string s.
func unescape(s string) string {
	var b bytes.Buffer
	for len(s) > 0 {
		if len(s) >= 3 && s[0] == '%' && isHex(s[1]) && isHex(s[2]) {
			b.WriteByte(unhex(s[1])<<4 | unhex(s[2]))
			s = s[3:]
		} else {
			b.WriteByte(s[0])
			s = s[1:]
		}
	}
	return b.String()
}

// recursiveUnescape unescapes the string s recursively until it cannot be
// unescaped anymore. It reports an error if the unescaping process seemed to
// have no end.
func recursiveUnescape(s string) (string, error) {
	const maxDepth = 1024
	for i := 0; i < maxDepth; i++ {
		t := unescape(s)
		if t == s {
			return s, nil
		}
		s = t
	}
	return "", errors.New("safebrowsing: unescaping is too recursive")
}

// normalizeEscape performs a recursive unescape and then escapes the string
// exactly once. It reports an error if it was unable to unescape the string.
func normalizeEscape(s string) (string, error) {
	u, err := recursiveUnescape(s)
	if err != nil {
		return "", err
	}
	return escape(u), nil
}

// getScheme splits the url into (scheme, path) where scheme is the protocol.
// If the scheme cannot be determined ("", url) is returned.
func getScheme(url string) (scheme, path string) {
	for i, c := range []byte(url) {
		switch {
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z':
			// Do nothing.
		case '0' <= c && c <= '9' || c == '+' || c == '-' || c == '.':
			if i == 0 {
				return "", url
			}
		case c == ':':
			return url[:i], url[i+1:]
		default:
			// Invalid character, so there is no valid scheme.
			return "", url
		}
	}
	return "", url
}

// parseHost parses a string to get host by the stripping the
// username, password, and port.
func parseHost(hostish string) (host string, err error) {
	i := strings.LastIndex(hostish, "@")
	if i < 0 {
		host = hostish
	} else {
		host = hostish[i+1:]
	}
	if strings.HasPrefix(host, "[") {
		// Parse an IP-Literal per RFC 3986 and RFC 6874.
		// For example: "[fe80::1] or "[fe80::1%25en0]"
		i := strings.LastIndex(host, "]")
		if i < 0 {
			return "", errors.New("safebrowsing: missing ']' in host")
		}
	}
	// Remove the port if it is there.
	host = portRegexp.ReplaceAllString(host, "")

	// Convert internationalized hostnames to IDNA.
	u := unescape(host)
	if isUnicode(u) {
		host, err = idna.ToASCII(u)
		if err != nil {
			return "", err
		}
	}

	// Remove any superfluous '.' characters in the hostname.
	host = dotsRegexp.ReplaceAllString(host, ".")
	host = strings.Trim(host, ".")
	// Canonicalize IP addresses.
	if iphost := parseIPAddress(host); iphost != "" {
		host = iphost
	} else {
		host = strings.ToLower(host)
	}
	return host, nil
}

// parseURL parses urlStr as a url.URL and reports an error if not possible.
func parseURL(urlStr string) (parsedURL *url.URL, err error) {
	// For legacy reasons, this is a simplified version of the net/url logic.
	//
	// Few cases where net/url was not helpful:
	// 1. URLs are are expected to have no escaped encoding in the host but to
	// be escaped in the path. Safe Browsing allows escaped characters in both.
	// 2. Also it has different behavior with and without a scheme for absolute
	// paths. Safe Browsing test web URLs only; and a scheme is optional.
	// If missing, we assume that it is an "http".
	// 3. We strip off the fragment and the escaped query as they are not
	// required for building patterns for Safe Browsing.

	parsedURL = new(url.URL)
	// Remove the URL fragment.
	// Also, we decode and encode the URL.
	// The '#' in a fragment is not friendly to that.
	rest, _ := split(urlStr, "#", true)
	// Start by stripping any leading and trailing whitespace.
	rest = strings.TrimSpace(rest)
	// Remove any embedded tabs and CR/LF characters which aren't escaped.
	rest = strings.Replace(rest, "\t", "", -1)
	rest = strings.Replace(rest, "\r", "", -1)
	rest = strings.Replace(rest, "\n", "", -1)
	rest, err = normalizeEscape(rest)
	if err != nil {
		return nil, err
	}
	parsedURL.Scheme, rest = getScheme(rest)
	rest, parsedURL.RawQuery = split(rest, "?", true)

	// Add HTTP as scheme if none.
	var hostish string
	if !strings.HasPrefix(rest, "//") && parsedURL.Scheme != "" {
		return nil, errors.New("safebrowsing: invalid path")
	}
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "http"
		hostish, rest = split(rest, "/", false)
	} else {
		hostish, rest = split(rest[2:], "/", false)
	}
	if hostish == "" {
		return nil, errors.New("safebrowsing: missing hostname")
	}

	parsedURL.Host, err = parseHost(hostish)
	if err != nil {
		return nil, err
	}
	// Format the path.
	p := path.Clean(rest)
	if p == "." {
		p = "/"
	} else if rest[len(rest)-1] == '/' && p[len(p)-1] != '/' {
		p += "/"
	}
	parsedURL.Path = p
	return parsedURL, nil
}

func parseIPAddress(iphostname string) string {
	// The Windows resolver allows a 4-part dotted decimal IP address to have a
	// space followed by any old rubbish, so long as the total length of the
	// string doesn't get above 15 characters. So, "10.192.95.89 xy" is
	// resolved to 10.192.95.89. If the string length is greater than 15
	// characters, e.g. "10.192.95.89 xy.wildcard.example.com", it will be
	// resolved through DNS.
	if len(iphostname) <= 15 {
		match := trailingSpaceRegexp.FindString(iphostname)
		if match != "" {
			iphostname = strings.TrimSpace(match)
		}
	}
	if !possibleIPRegexp.MatchString(iphostname) {
		return ""
	}
	parts := strings.Split(iphostname, ".")
	if len(parts) > 4 {
		return ""
	}
	ss := make([]string, len(parts))
	for i, n := range parts {
		if i == len(parts)-1 {
			ss[i] = canonicalNum(n, 5-len(parts))
		} else {
			ss[i] = canonicalNum(n, 1)
		}
		if ss[i] == "" {
			return ""
		}
	}
	return strings.Join(ss, ".")
}

// canonicalNum parses s as an integer and attempts to encode it as a '.'
// separated string where each element is the base-10 encoded value of each byte
// for the corresponding number, starting with the MSB. The result is one that
// is usable as an IP address.
//
// For example:
//	s:"01234",      n:2  =>  "2.156"
//	s:"0x10203040", n:4  =>  "16.32.48.64"
func canonicalNum(s string, n int) string {
	if n <= 0 || n > 4 {
		return ""
	}
	v, err := strconv.ParseUint(s, 0, 32)
	if err != nil {
		return ""
	}
	ss := make([]string, n)
	for i := n - 1; i >= 0; i-- {
		ss[i] = strconv.Itoa(int(v) & 0xff)
		v = v >> 8
	}
	return strings.Join(ss, ".")
}

// canonicalURL parses a URL string and returns it as scheme://hostname/path.
// It strips off fragments and queries.
func canonicalURL(u string) (string, error) {
	parsedURL, err := parseURL(u)
	if err != nil {
		return "", err
	}
	// Assemble the URL ourselves to skip encodings from the net/url package.
	u = parsedURL.Scheme + "://" + parsedURL.Host
	if parsedURL.Path == "" {
		return u + "/", nil
	}
	u += parsedURL.Path
	return u, nil
}

func canonicalHost(urlStr string) (string, error) {
	parsedURL, err := parseURL(urlStr)
	if err != nil {
		return "", err
	}

	return parsedURL.Host, nil
}

// generateLookupHosts returns a list of host-suffixes for the input URL.
func generateLookupHosts(urlStr string) ([]string, error) {
	// Safe Browsing policy asks to generate lookup hosts for the URL.
	// Those are formed by the domain and also up to 4 hostnames suffixes.
	// The last component or sometimes the pair isn't examined alone,
	// since it's the TLD or country code. The database for TLDs is here:
	//	https://publicsuffix.org/list/
	//
	// Note that we do not need to be clever about stopping at the "real" TLD.
	// We just check a few extra components regardless. It's not significantly
	// slower on the server side to check some extra hashes. Also the client
	// does not need to keep a database of TLDs.
	const maxHostComponents = 7

	host, err := canonicalHost(urlStr)
	if err != nil {
		return nil, err
	}
	// handle IPv4 and IPv6 addresses.
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip != nil {
		return []string{host}, nil
	}
	hostComponents := strings.Split(host, ".")

	numComponents := len(hostComponents) - maxHostComponents
	if numComponents < 1 {
		numComponents = 1
	}

	hosts := []string{host}
	for i := numComponents; i < len(hostComponents)-1; i++ {
		hosts = append(hosts, strings.Join(hostComponents[i:], "."))
	}
	return hosts, nil
}

func canonicalPath(urlStr string) (string, error) {
	// Note that this function is not used, but remains to ensure that the
	// parsedURL.Path output matches C++ implementation.
	parsedURL, err := parseURL(urlStr)
	if err != nil {
		return "", err
	}
	return parsedURL.Path, nil
}

// generateLookupPaths returns a list path-prefixes for the input URL.
func generateLookupPaths(urlStr string) ([]string, error) {
	const maxPathComponents = 4

	parsedURL, err := parseURL(urlStr)
	if err != nil {
		return nil, err
	}
	path := parsedURL.Path

	paths := []string{"/"}
	var pathComponents []string
	for _, p := range strings.Split(path, "/") {
		if p != "" {
			pathComponents = append(pathComponents, p)
		}
	}

	numComponents := len(pathComponents)
	if numComponents > maxPathComponents {
		numComponents = maxPathComponents
	}

	for i := 1; i < numComponents; i++ {
		paths = append(paths, "/"+strings.Join(pathComponents[:i], "/")+"/")
	}
	if path != "/" {
		paths = append(paths, path)
	}
	if len(parsedURL.RawQuery) > 0 {
		paths = append(paths, path+"?"+parsedURL.RawQuery)
	}
	return paths, nil
}
