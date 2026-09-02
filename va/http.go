package va

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/iana"
	"github.com/letsencrypt/boulder/identifier"
)

const (
	// maxRequests is the maximum number of HTTP requests the VA will make while
	// processing a single HTTP-01 challenge.
	maxRequests = 10
	// maxResponseSize holds the maximum number of bytes that will be read from an
	// HTTP-01 challenge response. The expected payload should be ~87 bytes. Since
	// it may be padded by whitespace which we previously allowed accept up to 128
	// bytes before rejecting a response (32 byte b64 encoded token + . + 32 byte
	// b64 encoded key fingerprint).
	maxResponseSize = 128
	// maxPathSize is the maximum number of bytes we will accept in the path of a
	// redirect URL.
	maxPathSize = 2000
)

// preresolvedDialer is a struct type that provides a DialContext function which
// will connect to the provided IP and port instead of letting DNS resolve
// The hostname of the preresolvedDialer is used to ensure the dial only completes
// using the pre-resolved IP/port when used for the correct host.
type preresolvedDialer struct {
	ip       netip.Addr
	port     string
	hostname string
	timeout  time.Duration
}

// a dialerMismatchError is produced when a preresolvedDialer is used to dial
// a host other than the dialer's specified hostname.
type dialerMismatchError struct {
	// The original dialer information
	dialerHost string
	dialerIP   string
	dialerPort string
	// The host that the dialer was incorrectly used with
	host string
}

func (e *dialerMismatchError) Error() string {
	return fmt.Sprintf(
		"preresolvedDialer mismatch: dialer is for %q (ip: %q port: %s) not %q",
		e.dialerHost, e.dialerIP, e.dialerPort, e.host)
}

// DialContext for a preresolvedDialer shaves 10ms off of the context it was
// given before calling the default transport DialContext using the pre-resolved
// IP and port as the host. If the original host being dialed by DialContext
// does not match the expected hostname in the preresolvedDialer an error will
// be returned instead. This helps prevents a bug that might use
// a preresolvedDialer for the wrong host.
//
// Shaving the context helps us be able to differentiate between timeouts during
// connect and timeouts after connect.
//
// Using preresolved information for the host argument given to the real
// transport dial lets us have fine grained control over IP address resolution for
// domain names.
func (d *preresolvedDialer) DialContext(
	ctx context.Context,
	network,
	origAddr string) (net.Conn, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		// Shouldn't happen: All requests should have a deadline by this point.
		deadline = time.Now().Add(100 * time.Second)
	} else {
		// Set the context deadline slightly shorter than the HTTP deadline, so we
		// get a useful error rather than a generic "deadline exceeded" error. This
		// lets us give a more specific error to the subscriber.
		deadline = deadline.Add(-10 * time.Millisecond)
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	// NOTE(@cpu): I don't capture and check the origPort here because using
	// `net.SplitHostPort` and also supporting the va's custom httpPort and
	// httpsPort is cumbersome. The initial origAddr may be "example.com:80"
	// if the URL used for the dial input was "http://example.com" without an
	// explicit port. Checking for equality here will fail unless we add
	// special case logic for converting 80/443 -> httpPort/httpsPort when
	// configured. This seems more likely to cause bugs than catch them so I'm
	// ignoring this for now. In the future if we remove the httpPort/httpsPort
	// (we should!) we can also easily enforce that the preresolved dialer port
	// matches expected here.
	origHost, _, err := net.SplitHostPort(origAddr)
	if err != nil {
		return nil, err
	}

	// If the hostname we're dialing isn't equal to the hostname the dialer was
	// constructed for then a bug has occurred where we've mismatched the
	// preresolved dialer.
	if origHost != d.hostname {
		return nil, &dialerMismatchError{
			dialerHost: d.hostname,
			dialerIP:   d.ip.String(),
			dialerPort: d.port,
			host:       origHost,
		}
	}

	// Make a new dial address using the pre-resolved IP and port.
	targetAddr := net.JoinHostPort(d.ip.String(), d.port)

	// Create a throw-away dialer using default values and the dialer timeout
	// (populated from the VA singleDialTimeout).
	throwAwayDialer := &net.Dialer{
		Timeout: d.timeout,
		// Default KeepAlive - see Golang src/net/http/transport.go DefaultTransport
		KeepAlive: 30 * time.Second,
	}
	return throwAwayDialer.DialContext(ctx, network, targetAddr)
}

// a dialerFunc meets the function signature requirements of
// a http.Transport.DialContext handler.
type dialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// httpTransport constructs a HTTP Transport with settings appropriate for
// HTTP-01 validation. The provided dialerFunc is used as the Transport's
// DialContext handler.
func httpTransport(df dialerFunc) *http.Transport {
	return &http.Transport{
		DialContext: df,
		// We are talking to a client that does not yet have a certificate,
		// so we accept a temporary, invalid one.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		// We don't expect to make multiple requests to a client, so close
		// connection immediately.
		DisableKeepAlives: true,
		// We don't want idle connections, but 0 means "unlimited," so we pick 1.
		MaxIdleConns:        1,
		IdleConnTimeout:     time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

// newValidationRecord creates a ValidationRecord for a validation request
// against the given URL, including port. This may involve querying DNS for the
// host's IP address, if the URL isn't an IP already. The resulting record's
// AddressUsed is the host's first IPv6 address, or its first IPv4 address if it
// has no IPv6 addresses.
//
// This function also enforces our policies around hosts we're unwilling to
// connect to during validation, such as private names and addresses, reserved
// names and addresses, non-HTTP(s) schemes, disallowed ports, and more.
func (va *ValidationAuthorityImpl) newValidationRecord(ctx context.Context, url url.URL) (core.ValidationRecord, error) {
	// The scheme must be HTTP or HTTPS.
	if url.Scheme != "http" && url.Scheme != "https" {
		return core.ValidationRecord{}, berrors.ConnectionFailureError(
			`invalid protocol scheme: only "http" and "https" are supported, not %q`, url.Scheme)
	}

	// The port must be one of the allowed ports, or empty. If it is empty, set
	// it to be the default port associated with the URL's scheme.
	port := url.Port()
	if port != "" {
		parsedPort, err := strconv.Atoi(port)
		if err != nil {
			return core.ValidationRecord{}, berrors.ConnectionFailureError(
				"invalid port %q: must be an integer", port)
		}

		if parsedPort != va.httpPort && parsedPort != va.httpsPort {
			return core.ValidationRecord{}, berrors.ConnectionFailureError(
				"invalid port %d: must be %d or %d", parsedPort, va.httpPort, va.httpsPort)
		}
	} else {
		if url.Scheme == "https" {
			port = strconv.Itoa(va.httpsPort)
		} else {
			port = strconv.Itoa(va.httpPort)
		}
	}

	// The path must be reasonably short.
	if len(url.Path) > maxPathSize {
		return core.ValidationRecord{}, berrors.ConnectionFailureError(
			"invalid url: path component too long")
	}

	// The host must be non-empty and comply with our validation policies.
	host := url.Hostname()
	if len(host) == 0 {
		return core.ValidationRecord{}, berrors.ConnectionFailureError(
			"invalid host: host must be non-empty")
	}

	var addrs []netip.Addr
	var resolvers []string

	parsedIP, err := netip.ParseAddr(host)
	isIP := err == nil
	if isIP {
		// Reject IPv6 addresses with a scope zone (RFCs 4007 & 6874)
		if parsedIP.Zone() != "" {
			return core.ValidationRecord{}, berrors.ConnectionFailureError("invalid host: contains IPv6 scope zone")
		}

		// Reject reserved IP addresses.
		err := va.isReservedIPFunc(parsedIP)
		if err != nil {
			return core.ValidationRecord{}, berrors.ConnectionFailureError("invalid host: %s", err)
		}

		// No need to resolve anything.
		addrs = []netip.Addr{parsedIP}
	} else {
		// Reject non-public domain names.
		_, err = iana.ExtractSuffix(host)
		if err != nil {
			return core.ValidationRecord{}, berrors.ConnectionFailureError("invalid host: must end in IANA registered TLD")
		}

		// Resolve IP addresses for the identifier
		addrs, resolvers, err = va.getAddrs(ctx, host)
		if err != nil {
			return core.ValidationRecord{}, err
		}
	}

	// Prefer the first IPv6 address, falling back to the first IPv4 address.
	v4Addrs, v6Addrs := availableAddresses(addrs)
	var addressUsed netip.Addr
	if len(v6Addrs) > 0 {
		addressUsed = v6Addrs[0]
	} else if len(v4Addrs) > 0 {
		addressUsed = v4Addrs[0]
	} else {
		return core.ValidationRecord{}, fmt.Errorf("host %q has no IPv4 or IPv6 addresses", host)
	}

	record := core.ValidationRecord{
		URL:               url.String(),
		Hostname:          host,
		Port:              port,
		AddressesResolved: addrs,
		AddressUsed:       addressUsed,
		ResolverAddrs:     resolvers,
	}

	return record, nil
}

// newValidationRecordFromFallback returns true and a copy of the given record
// with its AddressUsed replaced by the first IPv4 address from
// AddressesResolved if an IPv6-to-IPv4 fallback is possible. If fallback is not
// possible (either because the previous request already was to an IPv4 address,
// or no IPv4 addresses are available), it returns an empty record and false.
func newValidationRecordFromFallback(record core.ValidationRecord) (core.ValidationRecord, bool) {
	// If the previous request was already IPv4, there's no fallback to do.
	if record.AddressUsed.Is4() {
		return core.ValidationRecord{}, false
	}

	v4s, _ := availableAddresses(record.AddressesResolved)
	if len(v4s) == 0 {
		return core.ValidationRecord{}, false
	}

	// Modifying in-place is safe because we're passing records by value.
	record.AddressUsed = v4s[0]
	return record, true
}

// newValidationRecordFromRedirect constructs (including DNS resolution, if
// necessary) and returns a ValidationRecord representing the target of the
// redirect. It enforces our redirect policies (only specific HTTP status codes,
// no loops, etc.), and returns an empty record and an error if any policies are
// violated or DNS lookups fail.
func (va *ValidationAuthorityImpl) newValidationRecordFromRedirect(ctx context.Context, resp *http.Response, records []core.ValidationRecord) (core.ValidationRecord, error) {
	redirURL, err := resp.Location()
	if err != nil {
		return core.ValidationRecord{}, &url.Error{
			Op:  "Get",
			URL: resp.Request.URL.String(),
			Err: berrors.ConnectionFailureError("Invalid Location header in %d redirect", resp.StatusCode),
		}
	}
	va.log.Debugf("processing a HTTP redirect from the server to %q", redirURL.String())
	va.metrics.http01Redirects.Inc()

	// badRedirect wraps an error in a url.Error naming the rejected redirect
	// target. This mirrors the stdlib's redirect error behavior.
	badRedirect := func(err error) error {
		return &url.Error{Op: "Get", URL: redirURL.String(), Err: err}
	}

	// Lowercase the redirect host immediately, as the dialer and redirect
	// validation expect it to have been lowercased already.
	redirURL.Host = strings.ToLower(redirURL.Host)

	// Often folks will misconfigure their webserver to send an HTTP redirect
	// missing a `/' between the FQDN and the path. E.g. in Apache using:
	//   Redirect / https://bad-redirect.org
	// Instead of
	//   Redirect / https://bad-redirect.org/
	// Will produce an invalid HTTP-01 redirect target like:
	//   https://bad-redirect.org.well-known/acme-challenge/xxxx
	// This happens frequently enough we want to return a distinct error message
	// for this case by detecting the redirHost ending in ".well-known".
	if strings.HasSuffix(redirURL.Hostname(), ".well-known") {
		return core.ValidationRecord{}, badRedirect(berrors.ConnectionFailureError(
			"invalid host in redirect target %q: check webserver config for missing '/' in redirect target",
			redirURL.Hostname(),
		))
	}

	// Check for a redirect loop. If any URL is requested twice before the
	// request limit, return error.
	for _, record := range records {
		if redirURL.String() == record.URL {
			return core.ValidationRecord{}, badRedirect(berrors.ConnectionFailureError("redirect loop detected"))
		}
	}

	// Create a validation record for a request to the redirect target. This
	// will resolve IP addresses for the host explicitly.
	redirRecord, err := va.newValidationRecord(ctx, *redirURL)
	if err != nil {
		return core.ValidationRecord{}, badRedirect(err)
	}

	return redirRecord, nil
}

// doValidationRequest makes a single HTTP-01 validation request: a GET for
// the given validation record's URL, connecting to the record's AddressUsed
// and Port no matter what hostname the URL contains. If referer is non-empty
// it is sent as the Referer header.
func (va *ValidationAuthorityImpl) doValidationRequest(ctx context.Context, record core.ValidationRecord, referer string) (*http.Response, error) {
	// This is a backstop check to avoid connecting to reserved IP addresses.
	// They should have been caught and excluded by `bdns.LookupHost`.
	err := va.isReservedIPFunc(record.AddressUsed)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", record.URL, nil)
	if err != nil {
		return nil, err
	}

	if va.userAgent != "" {
		req.Header.Set("User-Agent", va.userAgent)
	}

	// Some of our users use mod_security. Mod_security sees a lack of Accept
	// headers as bot behavior and rejects requests. While this is a bug in
	// mod_security's rules (given that the HTTP specs disagree with that
	// requirement), we add the Accept header now in order to fix our
	// mod_security users' mysterious breakages. See
	// <https://github.com/SpiderLabs/owasp-modsecurity-crs/issues/265> and
	// <https://github.com/letsencrypt/boulder/issues/1019>. This was done
	// because it's a one-line fix with no downside. We're not likely to want to
	// do many more things to satisfy misunderstandings around HTTP.
	req.Header.Set("Accept", "*/*")
	if referer != "" {
		req.Header.Set("Referer", referer)
	}

	dialer := &preresolvedDialer{
		ip:       record.AddressUsed,
		port:     record.Port,
		hostname: record.Hostname,
		timeout:  va.singleDialTimeout,
	}
	client := &http.Client{
		Transport: httpTransport(dialer.DialContext),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// Return redirect responses to us, rather than following them.
			return http.ErrUseLastResponse
		},
	}
	return client.Do(req)
}

// fallbackErr returns true only for errors that occurred during net.Dial.
func fallbackErr(err error) bool {
	// Err shouldn't ever be nil if we're considering it for fallback
	if err == nil {
		return false
	}

	// Net OpErrors are fallback errs only if the operation was a "dial"
	netOpError, ok := errors.AsType[*net.OpError](err)
	if ok && netOpError.Op == "dial" {
		return true
	}

	// All other errs are not fallback errs
	return false
}

// processHTTPValidation performs an HTTP validation for the given identifier
// and path. If successful, the body of the final HTTP response is returned
// along with the ValidationRecords created during the validation. If not
// successful, a non-nil error and potentially some ValidationRecords are
// returned.
func (va *ValidationAuthorityImpl) processHTTPValidation(
	ctx context.Context,
	ident identifier.ACMEIdentifier,
	path string) ([]byte, []core.ValidationRecord, error) {
	// If the identifier is an IPv6 address, we need to enclose it in square
	// brackets, per RFC 3986, Section 3.2.2.
	host := ident.Value
	if ident.Type == identifier.TypeIP && netip.MustParseAddr(ident.Value).Is6() {
		host = "[" + host + "]"
	}

	// Create a record for the initial request: an http URL for the given path
	// under the identifier itself, with no query parameters.
	record, err := va.newValidationRecord(ctx, url.URL{
		Scheme: "http",
		Host:   host,
		Path:   path,
	})
	if err != nil {
		return nil, nil, err
	}

	// Shave some time from the overall context deadline so that we are not
	// racing with gRPC when the HTTP server is timing out. This avoids
	// returning ServerInternal errors when we should be returning Connection
	// errors.
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, nil, fmt.Errorf("processHTTPValidation had no deadline")
	} else {
		deadline = deadline.Add(-200 * time.Millisecond)
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	// referer holds the Referer header for the next request. We track this
	// ourselves so that we can send the referer header for both redirects and
	// IPv4 fallbacks of those redirects.
	referer := ""

	// Make requests until one of them yields a final (non-redirect) response, a
	// final (non-fallback) error, or we run out of retries. Each iteration of
	// this loop makes one request and appends one ValidationRecord.
	var records []core.ValidationRecord
	for range maxRequests {
		records = append(records, record)

		resp, err := va.doValidationRequest(ctx, record, referer)
		if err != nil {
			if fallbackErr(err) && ctx.Err() == nil {
				fallbackRecord, ok := newValidationRecordFromFallback(record)
				if ok {
					va.metrics.http01Fallbacks.Inc()
					record = fallbackRecord
					continue
				}
			}
			return nil, records, newIPError(record.AddressUsed, err)
		}

		// The four allowed redirect status codes are defined explicitly in BRs
		// Section 3.2.2.4.19; anything else (e.g. an HTTP 303) must not be
		// followed.
		allowedRedirect := resp.StatusCode == 301 || resp.StatusCode == 302 ||
			resp.StatusCode == 307 || resp.StatusCode == 308
		if allowedRedirect {
			_ = resp.Body.Close()

			redirRecord, redirErr := va.newValidationRecordFromRedirect(ctx, resp, records)
			if redirErr != nil {
				// redirErr is already wrapped in a url.Error naming the
				// rejected redirect target.
				return nil, records, newIPError(record.AddressUsed, redirErr)
			}
			va.log.Debugf("following redirect to %q", redirRecord.URL)

			// Like the stdlib http.Client, don't send a Referer header when
			// following a redirect from an HTTPS URL to an HTTP URL, and
			// never include userinfo in it.
			if resp.Request.URL.Scheme == "https" && strings.HasPrefix(redirRecord.URL, "http://") {
				referer = ""
			} else {
				refererURL := *resp.Request.URL
				refererURL.User = nil
				referer = refererURL.String()
			}

			record = redirRecord
			continue
		}

		// Special error case for disallowed 3xx status codes, since clients might
		// be surprised by this particular failure case.
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			_ = resp.Body.Close()
			return nil, records, newIPError(record.AddressUsed, berrors.ConnectionFailureError("Received disallowed redirect status code %d", resp.StatusCode))
		}

		// This is the final response: check its status code and return its body.
		if resp.StatusCode != 200 {
			_ = resp.Body.Close()
			return nil, records, newIPError(record.AddressUsed, berrors.UnauthorizedError("Invalid response from %s: %d", record.URL, resp.StatusCode))
		}

		body, err := io.ReadAll(core.ErrOnLimitReader(resp.Body, maxResponseSize))
		_ = resp.Body.Close()
		if err != nil {
			return nil, records, newIPError(record.AddressUsed, berrors.UnauthorizedError("Error reading HTTP response body: %v", err))
		}

		return body, records, nil
	}

	// If we made it to the end of the loop without returning, we maxed out the
	// number of requests we're willing to make.
	return nil, records, berrors.ConnectionFailureError("Too many hops")
}

func (va *ValidationAuthorityImpl) validateHTTP01(ctx context.Context, ident identifier.ACMEIdentifier, token string, keyAuthorization string) ([]core.ValidationRecord, error) {
	if ident.Type != identifier.TypeDNS && ident.Type != identifier.TypeIP {
		va.log.Errf("Identifier type for HTTP-01 challenge was not DNS or IP: %s", ident)
		return nil, berrors.MalformedError("Identifier type for HTTP-01 challenge was not DNS or IP")
	}

	// Perform the fetch
	path := fmt.Sprintf(".well-known/acme-challenge/%s", token)
	body, validationRecords, err := va.processHTTPValidation(ctx, ident, "/"+path)
	if err != nil {
		return validationRecords, err
	}
	payload := strings.TrimRightFunc(string(body), unicode.IsSpace)

	if payload != keyAuthorization {
		problem := berrors.UnauthorizedError("The key authorization file from the server did not match this challenge. Expected %q (got %q)",
			keyAuthorization, payload)
		va.log.Infof("%s for %s", problem, ident)
		return validationRecords, problem
	}

	return validationRecords, nil
}
