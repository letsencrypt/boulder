/*
Copyright (c) 2013, Richard Johnson
Copyright (c) 2014, Kilian Gilonne
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package safebrowsing

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Canonicalize a URL as needed for safe browsing lookups.
// This is required before obtaining the host key or generating
// url lookup iterations.
func Canonicalize(fullurl string) (canonicalized string) {
	// basic trim
	fullurl = strings.TrimSpace(fullurl)
	// add default http protocol
	re := regexp.MustCompile("[a-zA-Z][a-zA-Z0-9+-.]*://.*")
	if !re.Match([]byte(fullurl)) {
		fullurl = "http://" + fullurl
	}

	// strip off the fragment (if it exists)
	fullurl = strings.Split(fullurl, "#")[0]
	// remove any tab (0x09), CR (0x0d), and LF (0x0a)
	fullurl = strings.Replace(fullurl, "\t", "", -1)
	fullurl = strings.Replace(fullurl, "\n", "", -1)
	fullurl = strings.Replace(fullurl, "\r", "", -1)
	// unescape until there are no more encoded chars
	for newurl, performedUnescape := unescape(fullurl); performedUnescape; {
		fullurl = newurl
		newurl, performedUnescape = unescape(fullurl)
	}
	// extract the hostname
	fullurl = canonicalizeHostname(fullurl)
	fullurl = canonicalizePath(fullurl)

	fullurl = escapeUrl(fullurl)

	return fullurl
}

func canonicalizeHostname(fullurl string) (canonicalized string) {
	// extract the hostname from the url
	re := regexp.MustCompile("[a-zA-Z][a-zA-Z0-9+-.]*://([^/]+)/.*")
	matches := re.FindAllSubmatch([]byte(fullurl), 1)
	if len(matches) > 0 {
		hostname := string(matches[0][1])

		// remove all leading and trailing dots
		canonicalized = strings.Trim(hostname, ".")
		// Replace consecutive dots with a single dot.
		re = regexp.MustCompile("\\.\\.*")
		canonicalized = re.ReplaceAllString(canonicalized, ".")
		// attempt to parse as a IP address.
		ip := net.ParseIP(canonicalized)
		if ip != nil {
			canonicalized = ip.String()
		}
		ipInt, err := strconv.ParseUint(canonicalized, 10, 0)
		if err == nil {
			// we were an int!
			canonicalized = fmt.Sprintf("%d.%d.%d.%d",
				(ipInt>>24)&0xFF,
				(ipInt>>16)&0xFF,
				(ipInt>>8)&0xFF,
				ipInt&0xFF)
		}
		canonicalized = strings.ToLower(canonicalized)
		canonicalized = strings.Replace(fullurl, hostname, canonicalized, 1)
		return canonicalized
	}
	return fullurl
}

func canonicalizePath(fullurl string) (canonicalized string) {
	re := regexp.MustCompile("[a-zA-Z][a-zA-Z0-9+-.]*://[^/]+(/[^?]+)")
	matches := re.FindAllSubmatch([]byte(fullurl), 1)
	if len(matches) > 0 {
		path := string(matches[0][1])
		// The sequences "/../" and "/./" in the path should be resolved,
		// by replacing "/./" with "/", and removing "/../" along with
		// the preceding path component.
		canonicalized = strings.Replace(path, "/./", "/", -1)
		re = regexp.MustCompile("/?[^/]+/\\.\\.(/|$)")
		canonicalized = re.ReplaceAllString(canonicalized, "/")
		re = regexp.MustCompile("//*")
		canonicalized = re.ReplaceAllString(canonicalized, "/")
		canonicalized = strings.Replace(fullurl, path, canonicalized, 1)
		return canonicalized
	}
	if fullurl[len(fullurl)-1] != '/' {
		fullurl = fullurl + "/"
	}
	return fullurl
}

func escapeUrl(url string) string {
	// percent-escape all characters in the URL which are <= ASCII 32,
	// >= 127, "#", or "%". The escapes should use uppercase hex characters.
	buf := bytes.Buffer{}
	buf.Grow(len(url))
	for _, b := range []byte(url) {
		switch {
		case b <= 32 || b >= 127 || b == '#' || b == '%':
			buf.WriteByte('%')
			buf.WriteString(hex.EncodeToString([]byte{b}))
		default:
			buf.WriteByte(b)
		}
	}
	return buf.String()
}

// custom version of unescape to work around potential errors
// that would otherwise throw off url.QueryUnescape
func unescape(s string) (string, bool) {
	// Count %, check that they're well-formed.
	n := 0
	t := make([]byte, len(s)-2*n)
	j := 0
	performedUnescape := false
	for i := 0; i < len(s); {
		switch s[i] {
		case '%':
			if i+2 >= len(s) || !ishex(s[i+1]) || !ishex(s[i+2]) {
				// we were an invalid encoding, copy a char and keep going
				t[j] = s[i]
				j++
				i++
			} else {
				t[j] = unhex(s[i+1])<<4 | unhex(s[i+2])
				performedUnescape = true
				j++
				i += 3
			}
		default:
			t[j] = s[i]
			j++
			i++
		}
	}
	return string(t[:j]), performedUnescape
}

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

func ishex(c byte) bool {
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

func iterateHostnames(fullurl string) (urls []string) {
	re := regexp.MustCompile("([a-zA-Z][a-zA-Z0-9+-.]*://)([^/]+)/.*")
	matches := re.FindAllSubmatch([]byte(fullurl), 1)
	if len(matches) > 0 {
		hostname := string(matches[0][2])
		ip := net.ParseIP(hostname)
		if ip != nil {
			// we're an IP!
			return []string{fullurl}
		}
		pathBits := strings.Split(hostname, ".")
		urls = make([]string, 0, len(pathBits))
		// add the initial one
		urls = append(urls, fullurl)
		if len(pathBits) > 1 {
			if len(pathBits) > 6 {
				pathBits = pathBits[len(pathBits)-6:]
			}
			newHost := pathBits[len(pathBits)-2] + "." + pathBits[len(pathBits)-1]
			urls = append(urls, strings.Replace(fullurl, hostname, newHost, 1))
			for x := len(pathBits) - 3; x > 0; x-- {
				newHost = pathBits[x] + "." + newHost
				newUrl := strings.Replace(fullurl, hostname, newHost, 1)
				urls = append(urls, newUrl)
			}
		}
		return urls
	}
	return []string{fullurl}
}

func iteratePaths(fullurl string) (urls []string) {
	re := regexp.MustCompile("([a-zA-Z][a-zA-Z0-9+-.]*://[^/]+)(/[^?]*)")
	matches := re.FindAllSubmatch([]byte(fullurl), 1)
	urls = make([]string, 0)
	if strings.ContainsRune(fullurl, '?') {
		// add original url
		urls = append(urls, fullurl)
	}
	if len(matches) > 0 {
		bits := matches[0]
		if len(bits) > 2 {
			path := string(bits[2])
			prefix := string(bits[1])
			// url without query string
			urls = append(urls, prefix+path)
			pathBits := strings.Split(path, "/")
			if len(pathBits) > 1 {
				// url without path
				prefix += "/"
				urls = append(urls, prefix)
				for x := 1; x < len(pathBits)-1 && x < 4; x++ {
					prefix += pathBits[x] + "/"
					urls = append(urls, prefix)
				}
			}
		}
	}
	return urls
}

func stripProtocol(fullurl string) (url string) {
	sep := "://"
	startByte := strings.Index(fullurl, sep)
	if startByte == -1 {
		return fullurl
	}
	startByte += len(sep)
	return fullurl[startByte:]
}

// Generate all required iterations of the URL for checking against the
// lookup table.
// NOTE: We assume that the URL has already be Canonicalized
func GenerateTestCandidates(url string) (urls []string) {
	urls = make([]string, 0)
	values := iterateHostnames(url)
	for _, val := range values {
		paths := iteratePaths(val)
		for _, path := range paths {
			path = stripProtocol(path)
			urls = append(urls, path)
		}
	}
	return urls
}

// Extract the host from a URL in a format suitable for hashing to generate
// a Host Key.
// NOTE: We assume that the URL has already be Canonicalized
func ExtractHostKey(fullUrl string) (url string) {
	// strip off protocol
	url = stripProtocol(fullUrl)
	// strip off the path
	index := strings.Index(url, "/")
	if index > 0 {
		url = url[:index+1]
	} else {
		url += "/"
	}
	dotCount := strings.Count(url, ".")
	for dotCount > 2 {
		url = url[strings.Index(url, ".")+1:]
		dotCount = strings.Count(url, ".")
	}
	return url
}
