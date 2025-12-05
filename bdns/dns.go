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

	queryTime       *prometheus.HistogramVec
	totalLookupTime *prometheus.HistogramVec
	timeoutCounter  *prometheus.CounterVec
}

var _ Client = &impl{}

// New constructs a new DNS resolver object that utilizes the provided list of
// DNS servers for resolution, and the provided tlsConfig to speak DoH to those
// servers.
func New(
	readTimeout time.Duration,
	servers ServerProvider,
	stats prometheus.Registerer,
	clk clock.Clock,
	maxTries int,
	userAgent string,
	log blog.Logger,
	tlsConfig *tls.Config,
) Client {
	// Clone the default transport because it comes with various settings that we
	// like, which are different from the zero value of an `http.Transport`. Then
	// set it to force HTTP/2, because Unbound will reject non-HTTP/2 DoH
	// requests.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	transport.ForceAttemptHTTP2 = true

	exchanger := &dohExchanger{
		clk: clk,
		hc: http.Client{
			Timeout:   readTimeout,
			Transport: transport,
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

	if maxTries < 1 {
		// Allowing negative or zero total attempts makes no sense, so default to 1.
		maxTries = 1
	}

	return &impl{
		exchanger:       exchanger,
		servers:         servers,
		maxTries:        maxTries,
		clk:             clk,
		queryTime:       queryTime,
		totalLookupTime: totalLookupTime,
		timeoutCounter:  timeoutCounter,
		log:             log,
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

	var resp *dns.Msg

	servers, err := c.servers.Addrs()
	if err != nil {
		return nil, "", fmt.Errorf("failed to list DNS servers: %w", err)
	}

	// Prepare to increment a latency metric no matter whether we succeed or fail.
	// The deferred function closes over result, chosenServerIP, and tries, which
	// are all modified in the loop below.
	start := c.clk.Now()
	qtypeStr := dns.TypeToString[qtype]
	result := "failed"
	chosenServerIP := ""
	tries := 0
	defer func() {
		if resp != nil {
			result = dns.RcodeToString[resp.Rcode]
		}
		c.totalLookupTime.With(prometheus.Labels{
			"qtype":    qtypeStr,
			"result":   result,
			"resolver": chosenServerIP,
			"attempts": strconv.Itoa(tries),
		}).Observe(c.clk.Since(start).Seconds())
	}()

	type dnsRes struct {
		resp *dns.Msg
		err  error
	}
	ch := make(chan dnsRes, 1)

	for i := range c.maxTries {
		tries = i + 1
		chosenServer := servers[i%len(servers)]

		// Strip off the IP address part of the server address because
		// we talk to the same server on multiple ports, and don't want
		// to blow up the cardinality.
		// Note: validateServerAddress() has already checked net.SplitHostPort()
		// and ensures that chosenServer can't be a bare port, e.g. ":1337"
		chosenServerIP, _, err = net.SplitHostPort(chosenServer)
		if err != nil {
			return nil, "", err
		}

		go func() {
			resp, rtt, err := c.exchanger.Exchange(req, chosenServer)
			result := "failed"
			if resp != nil {
				result = dns.RcodeToString[resp.Rcode]
			}
			if err != nil {
				c.log.Infof("logDNSError chosenServer=[%s] hostname=[%s] queryType=[%s] err=[%s]", chosenServer, hostname, qtypeStr, err)
			}
			c.queryTime.With(prometheus.Labels{
				"qtype":    qtypeStr,
				"result":   result,
				"resolver": chosenServerIP,
			}).Observe(rtt.Seconds())
			ch <- dnsRes{resp: resp, err: err}
		}()
		select {
		case <-ctx.Done():
			switch ctx.Err() {
			case context.DeadlineExceeded:
				result = "deadline exceeded"
			case context.Canceled:
				result = "canceled"
			default:
				result = "unknown"
			}
			c.timeoutCounter.With(prometheus.Labels{
				"qtype":    qtypeStr,
				"result":   result,
				"resolver": chosenServerIP,
				"isTLD":    fmt.Sprintf("%t", !strings.Contains(hostname, ".")),
			}).Inc()
			return nil, "", ctx.Err()
		case r := <-ch:
			if r.err != nil {
				// Check if the error is a timeout error, which we want to retry.
				// Network errors that can timeout implement the net.Error interface.
				var netErr net.Error
				isRetryable := errors.As(r.err, &netErr) && netErr.Timeout()
				hasRetriesLeft := tries < c.maxTries
				if isRetryable && hasRetriesLeft {
					continue
				} else if isRetryable && !hasRetriesLeft {
					c.timeoutCounter.With(prometheus.Labels{
						"qtype":    qtypeStr,
						"result":   "out of retries",
						"resolver": chosenServerIP,
						"isTLD":    fmt.Sprintf("%t", !strings.Contains(hostname, ".")),
					}).Inc()
				}
			}

			// This is either a success or a non-retryable error; return either way.
			return r.resp, chosenServer, r.err
		}
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

	return resultFromMsg[*dns.A](resp), resolver, wrapErr(dns.TypeA, hostname, resp, err)
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
	if err == nil && resp.Rcode == dns.RcodeNameError && strings.Contains(hostname, ".") {
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
	Exchange(m *dns.Msg, a string) (*dns.Msg, time.Duration, error)
}

// dohExchanger implements the exchanger interface. It routes all of its DNS
// queries over DoH, wrapping the request with the appropriate headers and
// unwrapping the response.
type dohExchanger struct {
	clk       clock.Clock
	hc        http.Client
	userAgent string
}

// Exchange sends a DoH query to the provided DoH server and returns the response.
func (d *dohExchanger) Exchange(query *dns.Msg, server string) (*dns.Msg, time.Duration, error) {
	q, err := query.Pack()
	if err != nil {
		return nil, 0, err
	}

	// The default Unbound URL template
	url := fmt.Sprintf("https://%s/dns-query", server)
	req, err := http.NewRequest("POST", url, strings.NewReader(string(q)))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	if len(d.userAgent) > 0 {
		req.Header.Set("User-Agent", d.userAgent)
	}

	start := d.clk.Now()
	resp, err := d.hc.Do(req)
	if err != nil {
		return nil, d.clk.Since(start), err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, d.clk.Since(start), fmt.Errorf("doh: http status %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, d.clk.Since(start), fmt.Errorf("doh: reading response body: %w", err)
	}

	response := new(dns.Msg)
	err = response.Unpack(b)
	if err != nil {
		return nil, d.clk.Since(start), fmt.Errorf("doh: unpacking response: %w", err)
	}

	return response, d.clk.Since(start), nil
}
