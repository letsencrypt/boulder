package bdns

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
)

// Result is a wrapper around miekg/dns.Msg, but with all Resource Records from
// the Answer section which match the parameterized record type already pulled
// out for convenient access.
type Result[R dns.RR] struct {
	*dns.Msg
	CNames []*dns.CNAME
	Final  []R
}

// resultFromMsg returns a Result whose CNames and Final fields are populated
// from the underlying Msg's Answer field.
func resultFromMsg[R dns.RR](m *dns.Msg) *Result[R] {
	var cnames []*dns.CNAME
	var final []R
	for _, rr := range m.Answer {
		if a, ok := rr.(R); ok {
			final = append(final, a)
		} else if a, ok := rr.(*dns.CNAME); ok {
			cnames = append(cnames, a)
		}
	}

	return &Result[R]{
		Msg:    m,
		CNames: cnames,
		Final:  final,
	}
}

// Client can make A, AAAA, CAA, and TXT queries. The second return value of
// each method is the address of the resolver used to conduct the query, and
// should be populated even when returning an error.
type Client interface {
	LookupA(context.Context, string) (*Result[*dns.A], string, error)
	LookupAAAA(context.Context, string) (*Result[*dns.AAAA], string, error)
	LookupCAA(context.Context, string) (*Result[*dns.CAA], string, error)
	LookupTXT(context.Context, string) (*Result[*dns.TXT], string, error)
}

// impl implements the Client interface via an underlying DNS exchanger. It
// rotates queries across multiple resolvers and tracks a variety of metrics.
type impl struct {
	exchanger exchanger
	servers   ServerProvider
	maxTries  int
	clk       clock.Clock
	log       blog.Logger

	queryTime          *prometheus.HistogramVec
	totalLookupTime    *prometheus.HistogramVec
	timeoutCounter     *prometheus.CounterVec
	dohTransportErrors *prometheus.CounterVec
}

var _ Client = &impl{}

// New constructs a new DNS resolver object that utilizes the provided list of
// DNS servers for resolution, and the provided tlsConfig to speak DoH to those
// servers.
func New(
	responseTimeout time.Duration,
	servers ServerProvider,
	stats prometheus.Registerer,
	clk clock.Clock,
	maxTries int,
	userAgent string,
	log blog.Logger,
	tlsConfig *tls.Config,
) Client {
	transport := &http.Transport{
		// Set short hardcoded timeouts for TCP connection and handshaking, since
		// we expect our recursive resolver to be local. If it takes a long
		// time to dial, something's wrong.
		TLSHandshakeTimeout: 2 * time.Second,
		DialContext: (&net.Dialer{
			Timeout: 2 * time.Second,
		}).DialContext,
		// Set a configurable timeout for how long to wait for an HTTP response.
		// Since the HTTP response blocks on recursive resolution, which relies on
		// potentially slow external servers, this will typically be larger than
		// the connection timeout.
		ResponseHeaderTimeout: responseTimeout,
		// Force HTTP/2 because Unbound will reject non-HTTP/2 DoH requests.
		ForceAttemptHTTP2: true,
		MaxIdleConns:      100,
		IdleConnTimeout:   90 * time.Second,
		TLSClientConfig:   tlsConfig,
	}

	exchanger := &dohExchanger{
		clk: clk,
		hc: http.Client{
			Transport: transport,
			Timeout:   0,
		},
		userAgent: userAgent,
	}

	queryTime := promauto.With(stats).NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "dns_query_time",
			Help:    "Time taken to perform a DNS query",
			Buckets: metrics.InternetFacingBuckets,
		},
		[]string{"qtype", "result", "resolver"},
	)
	totalLookupTime := promauto.With(stats).NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "dns_total_lookup_time",
			Help:    "Time taken to perform a DNS lookup, including all retried queries",
			Buckets: metrics.InternetFacingBuckets,
		},
		[]string{"qtype", "result", "resolver", "attempts"},
	)
	timeoutCounter := promauto.With(stats).NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_timeout",
			Help: "Counter of various types of DNS query timeouts",
		},
		[]string{"qtype", "result", "resolver", "isTLD"},
	)
	dohTransportErrors := promauto.With(stats).NewCounterVec(
		prometheus.CounterOpts{
			Name: "doh_transport_errors",
			Help: "Number of internal errors in DoH (e.g. connection refused, dial timeout, 400)",
		}, []string{"resolver"},
	)

	if maxTries < 1 {
		// Allowing negative or zero total attempts makes no sense, so default to 1.
		maxTries = 1
	}

	return &impl{
		exchanger:          exchanger,
		servers:            servers,
		maxTries:           maxTries,
		clk:                clk,
		queryTime:          queryTime,
		totalLookupTime:    totalLookupTime,
		timeoutCounter:     timeoutCounter,
		dohTransportErrors: dohTransportErrors,
		log:                log,
	}
}

// exchangeOne performs a single DNS exchange with a randomly chosen server out
// of the server list, returning the response, resolver used, and error (if
// any). If a response received indicates that the resolver encountered an error
// (such as an expired DNSSEC signature), that is converted into an error and
// returned.
func (c *impl) exchangeOne(ctx context.Context, hostname string, qtype uint16) (*dns.Msg, string, error) {
	req := new(dns.Msg)
	// Set question type
	req.SetQuestion(dns.Fqdn(hostname), qtype)
	// Set the AD bit in the query header so that the resolver knows that
	// we are interested in this bit in the response header. If this isn't
	// set the AD bit in the response is useless (RFC 6840 Section 5.7).
	// This has no security implications, it simply allows us to gather
	// metrics about the percentage of responses that are secured with
	// DNSSEC.
	req.AuthenticatedData = true
	// Tell the resolver that we're willing to receive responses up to 4096 bytes.
	// This happens sometimes when there are a very large number of CAA records
	// present.
	req.SetEdns0(4096, false)

	qBytes, err := req.Pack()
	if err != nil {
		return nil, "", err
	}

	servers, err := c.servers.Addrs()
	if err != nil {
		return nil, "", fmt.Errorf("failed to list DNS servers: %w", err)
	}

	// Prepare to increment a latency metric no matter whether we succeed or fail.
	// The deferred function closes over parsedResponse, chosenServer, and tries, which
	// are all modified in the loop below.
	start := c.clk.Now()
	qtypeStr := dns.TypeToString[qtype]
	var (
		parsedResponse *dns.Msg
		chosenServer   string
		tries          int
	)
	defer func() {
		result := "failed"
		if parsedResponse != nil {
			result = dns.RcodeToString[parsedResponse.Rcode]
		}
		c.totalLookupTime.With(prometheus.Labels{
			"qtype":    qtypeStr,
			"result":   result,
			"resolver": chosenServer,
			"attempts": strconv.Itoa(tries),
		}).Observe(c.clk.Since(start).Seconds())
	}()

	for i := range c.maxTries {
		tries = i + 1
		chosenServer = servers[i%len(servers)]

		queryBegin := c.clk.Now()
		resp, err := c.exchanger.dohQuery(ctx, qBytes, chosenServer)

		// Do some metrics handling before we do error handling.
		result := "ok"
		if err != nil {
			result = "failed"
		}
		c.queryTime.With(prometheus.Labels{
			"qtype":    qtypeStr,
			"result":   result,
			"resolver": chosenServer,
		}).Observe(c.clk.Since(queryBegin).Seconds())

		if err != nil {
			if !errors.Is(err, errDohQueryTimeout) && !errors.Is(err, errDohQueryCanceled) {
				c.dohTransportErrors.With(prometheus.Labels{"resolver": chosenServer}).Inc()
			} else {
				c.log.InfoObject("logDNSError", map[string]string{
					"resolver":  chosenServer,
					"hostname":  hostname,
					"queryType": qtypeStr,
					"err":       err.Error(),
				})
			}

			// Retry all errors up to the maxTries limit and the context deadline or cancellation.
			isRetryable := ctx.Err() == nil
			hasRetriesLeft := tries < c.maxTries
			if isRetryable && hasRetriesLeft {
				continue
			} else if isRetryable && !hasRetriesLeft {
				c.timeoutCounter.With(prometheus.Labels{
					"qtype":    qtypeStr,
					"result":   "out of retries",
					"resolver": chosenServer,
					"isTLD":    fmt.Sprintf("%t", !strings.Contains(hostname, ".")),
				}).Inc()
			} else if errors.Is(err, errDohQueryTimeout) {
				c.timeoutCounter.With(prometheus.Labels{
					"qtype":    qtypeStr,
					"result":   "deadline exceeded",
					"resolver": chosenServer,
					"isTLD":    fmt.Sprintf("%t", !strings.Contains(hostname, ".")),
				}).Inc()
			} else if errors.Is(err, errDohQueryCanceled) {
				c.timeoutCounter.With(prometheus.Labels{
					"qtype":    qtypeStr,
					"result":   "canceled",
					"resolver": chosenServer,
					"isTLD":    fmt.Sprintf("%t", !strings.Contains(hostname, ".")),
				}).Inc()
			}

			return nil, chosenServer, err
		}

		parsedResponse = new(dns.Msg)
		err = parsedResponse.Unpack(resp)
		if err != nil {
			return nil, chosenServer, fmt.Errorf("doh: unpacking response: %w", err)
		}

		return parsedResponse, chosenServer, nil
	}

	// It's impossible to get past the bottom of the loop: on the last attempt
	// (when tries == c.maxTries), all paths lead to a return from inside the loop.
	return nil, "", errors.New("unexpected loop escape in exchangeOne")
}

// LookupA sends a DNS query to find all A records associated with the provided
// hostname.
func (c *impl) LookupA(ctx context.Context, hostname string) (*Result[*dns.A], string, error) {
	resp, resolver, err := c.exchangeOne(ctx, hostname, dns.TypeA)
	err = wrapErr(dns.TypeA, hostname, resp, err)
	if err != nil {
		return nil, resolver, err
	}

	return resultFromMsg[*dns.A](resp), resolver, nil
}

// LookupAAAA sends a DNS query to find all AAAA records associated with the
// provided hostname.
func (c *impl) LookupAAAA(ctx context.Context, hostname string) (*Result[*dns.AAAA], string, error) {
	resp, resolver, err := c.exchangeOne(ctx, hostname, dns.TypeAAAA)
	err = wrapErr(dns.TypeAAAA, hostname, resp, err)
	if err != nil {
		return nil, resolver, err
	}

	return resultFromMsg[*dns.AAAA](resp), resolver, nil
}

// LookupCAA sends a DNS query to find all CAA records associated with the
// provided hostname.
func (c *impl) LookupCAA(ctx context.Context, hostname string) (*Result[*dns.CAA], string, error) {
	resp, resolver, err := c.exchangeOne(ctx, hostname, dns.TypeCAA)

	// Special case: when checking CAA for non-TLD names, treat NXDOMAIN as a
	// successful response containing an empty set of records. This can come up in
	// situations where records were provisioned for validation (e.g. TXT records
	// for DNS-01 challenge) and then removed after validation but before CAA
	// rechecking. But allow NXDOMAIN for TLDs to fall through to the error code
	// below, so we don't issue for gTLDs that have been removed by ICANN.
	// Truncated responses also fall through, since we can't definitively trust
	// an incomplete response to accurately reflect an NXDOMAIN.
	if err == nil && !resp.Truncated && resp.Rcode == dns.RcodeNameError && strings.Contains(hostname, ".") {
		return resultFromMsg[*dns.CAA](resp), resolver, nil
	}

	err = wrapErr(dns.TypeCAA, hostname, resp, err)
	if err != nil {
		return nil, resolver, err
	}

	return resultFromMsg[*dns.CAA](resp), resolver, nil
}

// LookupTXT sends a DNS query to find all TXT records associated with the
// provided hostname.
func (c *impl) LookupTXT(ctx context.Context, hostname string) (*Result[*dns.TXT], string, error) {
	resp, resolver, err := c.exchangeOne(ctx, hostname, dns.TypeTXT)
	err = wrapErr(dns.TypeTXT, hostname, resp, err)
	if err != nil {
		return nil, resolver, err
	}

	return resultFromMsg[*dns.TXT](resp), resolver, nil
}

// exchanger represents an underlying DNS client. This interface exists solely
// so that its implementation can be swapped out in unit tests.
type exchanger interface {
	dohQuery(ctx context.Context, queryBytes []byte, a string) ([]byte, error)
}

// dohExchanger implements the exchanger interface. It routes all of its DNS
// queries over DoH, wrapping the request with the appropriate headers and
// unwrapping the response.
type dohExchanger struct {
	clk       clock.Clock
	hc        http.Client
	userAgent string
}

// errDohQueryTimeout indicates an HTTP response timeout from Unbound, typically due to
// a slow authoritative server. It is also returned when the context deadline is
// exceeded during the HTTP query.
var errDohQueryTimeout = errors.New("query timed out")

// errDohQueryCanceled indicates a context cancellation while waiting for an HTTP response.
// This doesn't indicate a communication failure with Unbound, so we don't want it to
// count as a DoH transport error.
var errDohQueryCanceled = errors.New("query timed out (and was canceled)")

// dohQuery sends a DoH query to the provided DoH server and returns the response.
//
// Returns `dohQueryTimeout` or `dohQueryCanceled` if the HTTP request times out or is
// canceled (which generally indicates Somebody Else's Problem). All other errors, including
// connection refused, TLS handshake failures, or dial timeouts talking to Unbound, are
// of other error types and can be considered a DoH transport error.
func (d *dohExchanger) dohQuery(ctx context.Context, queryBytes []byte, server string) ([]byte, error) {
	// The default Unbound URL template
	url := fmt.Sprintf("https://%s/dns-query", server)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(queryBytes)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	if len(d.userAgent) > 0 {
		req.Header.Set("User-Agent", d.userAgent)
	}

	resp, err := d.hc.Do(req)
	if err != nil {
		// If the context is done, we'll consider that a user-caused error. Some of these
		// will actually be our fault. For instance, if a request came in with a
		// short deadline (in secondary validation), we could hit the context deadline
		// during Dial. In general we want Dial timeouts to be our fault, but since these
		// are ambiguous we'll err on the side of "don't alert," or in other words "consider
		// it a user-caused error". Most requests come in with plenty of deadline left, and
		// if Unbound is not responding, those other requests will show up in the "our fault"
		// bucket.
		if ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, errDohQueryTimeout
			}
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil, errDohQueryCanceled
			}
		}
		// Hack: The most common case for a user-caused error is that we hit
		// `http.Transport.ResponseHeaderTimeout`. This is what happens when we have
		// successfully connected to Unbound and sent a request, but Unbound is slow
		// to respond because the authoritative is slow to respond.
		//
		// The best way to distinguish these definitively is a string match on the error.
		// https://cs.opensource.google/go/go/+/refs/tags/go1.27.2:src/net/http/internal/http2/http2.go;l=374
		// https://cs.opensource.google/go/go/+/refs/tags/go1.27.2:src/net/http/internal/http2/transport.go;l=1383-1384
		//
		// Note in particular that matching on DeadlineExceeded would be wrong
		// because we can get an error matching `DeadlineExceeded` if the Dial times out.
		// See TestDialTimeoutError for confirmation.
		if strings.Contains(err.Error(), "timeout awaiting response headers") {
			return nil, errDohQueryTimeout
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: http status %d", resp.StatusCode)
	}

	// DNS response over 65535 is malformed https://datatracker.ietf.org/doc/html/rfc8484#section-6
	b, err := io.ReadAll(core.ErrOnLimitReader(resp.Body, 65_535))
	if err != nil {
		return nil, fmt.Errorf("doh: reading response body: %w", err)
	}

	return b, nil
}
