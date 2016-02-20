// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bdns

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/golang.org/x/net/context"
	"github.com/letsencrypt/boulder/metrics"
)

var (
	// Private CIDRs to ignore
	privateNetworks = []net.IPNet{
		// RFC1918
		// 10.0.0.0/8
		{
			IP:   []byte{10, 0, 0, 0},
			Mask: []byte{255, 0, 0, 0},
		},
		// 172.16.0.0/12
		{
			IP:   []byte{172, 16, 0, 0},
			Mask: []byte{255, 240, 0, 0},
		},
		// 192.168.0.0/16
		{
			IP:   []byte{192, 168, 0, 0},
			Mask: []byte{255, 255, 0, 0},
		},
		// RFC5735
		// 127.0.0.0/8
		{
			IP:   []byte{127, 0, 0, 0},
			Mask: []byte{255, 0, 0, 0},
		},
		// RFC1122 Section 3.2.1.3
		// 0.0.0.0/8
		{
			IP:   []byte{0, 0, 0, 0},
			Mask: []byte{255, 0, 0, 0},
		},
		// RFC3927
		// 169.254.0.0/16
		{
			IP:   []byte{169, 254, 0, 0},
			Mask: []byte{255, 255, 0, 0},
		},
		// RFC 5736
		// 192.0.0.0/24
		{
			IP:   []byte{192, 0, 0, 0},
			Mask: []byte{255, 255, 255, 0},
		},
		// RFC 5737
		// 192.0.2.0/24
		{
			IP:   []byte{192, 0, 2, 0},
			Mask: []byte{255, 255, 255, 0},
		},
		// 198.51.100.0/24
		{
			IP:   []byte{192, 51, 100, 0},
			Mask: []byte{255, 255, 255, 0},
		},
		// 203.0.113.0/24
		{
			IP:   []byte{203, 0, 113, 0},
			Mask: []byte{255, 255, 255, 0},
		},
		// RFC 3068
		// 192.88.99.0/24
		{
			IP:   []byte{192, 88, 99, 0},
			Mask: []byte{255, 255, 255, 0},
		},
		// RFC 2544
		// 192.18.0.0/15
		{
			IP:   []byte{192, 18, 0, 0},
			Mask: []byte{255, 254, 0, 0},
		},
		// RFC 3171
		// 224.0.0.0/4
		{
			IP:   []byte{224, 0, 0, 0},
			Mask: []byte{240, 0, 0, 0},
		},
		// RFC 1112
		// 240.0.0.0/4
		{
			IP:   []byte{240, 0, 0, 0},
			Mask: []byte{240, 0, 0, 0},
		},
		// RFC 919 Section 7
		// 255.255.255.255/32
		{
			IP:   []byte{255, 255, 255, 255},
			Mask: []byte{255, 255, 255, 255},
		},
		// RFC 6598
		// 100.64.0.0./10
		{
			IP:   []byte{100, 64, 0, 0},
			Mask: []byte{255, 192, 0, 0},
		},
	}
)

// DNSResolver queries for DNS records
type DNSResolver interface {
	LookupTXT(context.Context, string) (txts []string, authorities []string, err error)
	LookupHost(context.Context, string) ([]net.IP, error)
	LookupCAA(context.Context, string) ([]*dns.CAA, error)
	LookupMX(context.Context, string) ([]string, error)
}

// DNSResolverImpl represents a client that talks to an external resolver
type DNSResolverImpl struct {
	DNSClient                exchanger
	Servers                  []string
	allowRestrictedAddresses bool
	maxTries                 int
	clk                      clock.Clock
	stats                    metrics.Scope
	txtStats                 metrics.Scope
	aStats                   metrics.Scope
	caaStats                 metrics.Scope
	mxStats                  metrics.Scope
}

var _ DNSResolver = &DNSResolverImpl{}

type exchanger interface {
	Exchange(m *dns.Msg, a string) (*dns.Msg, time.Duration, error)
}

// NewDNSResolverImpl constructs a new DNS resolver object that utilizes the
// provided list of DNS servers for resolution.
func NewDNSResolverImpl(readTimeout time.Duration, servers []string, stats metrics.Scope, clk clock.Clock, maxTries int) *DNSResolverImpl {
	// TODO(jmhodges): make constructor use an Option func pattern
	dnsClient := new(dns.Client)

	// Set timeout for underlying net.Conn
	dnsClient.ReadTimeout = readTimeout
	dnsClient.Net = "tcp"

	return &DNSResolverImpl{
		DNSClient:                dnsClient,
		Servers:                  servers,
		allowRestrictedAddresses: false,
		maxTries:                 maxTries,
		clk:                      clk,
		stats:                    stats,
		txtStats:                 stats.NewScope("TXT"),
		aStats:                   stats.NewScope("A"),
		caaStats:                 stats.NewScope("CAA"),
		mxStats:                  stats.NewScope("MX"),
	}
}

// NewTestDNSResolverImpl constructs a new DNS resolver object that utilizes the
// provided list of DNS servers for resolution and will allow loopback addresses.
// This constructor should *only* be called from tests (unit or integration).
func NewTestDNSResolverImpl(readTimeout time.Duration, servers []string, stats metrics.Scope, clk clock.Clock, maxTries int) *DNSResolverImpl {
	resolver := NewDNSResolverImpl(readTimeout, servers, stats, clk, maxTries)
	resolver.allowRestrictedAddresses = true
	return resolver
}

// exchangeOne performs a single DNS exchange with a randomly chosen server
// out of the server list, returning the response, time, and error (if any).
// This method sets the DNSSEC OK bit on the message to true before sending
// it to the resolver in case validation isn't the resolvers default behaviour.
func (dnsResolver *DNSResolverImpl) exchangeOne(ctx context.Context, hostname string, qtype uint16, msgStats metrics.Scope) (*dns.Msg, error) {
	m := new(dns.Msg)
	// Set question type
	m.SetQuestion(dns.Fqdn(hostname), qtype)
	// Set DNSSEC OK bit for resolver
	m.SetEdns0(4096, true)

	if len(dnsResolver.Servers) < 1 {
		return nil, fmt.Errorf("Not configured with at least one DNS Server")
	}

	dnsResolver.stats.Inc("Rate", 1)

	// Randomly pick a server
	chosenServer := dnsResolver.Servers[rand.Intn(len(dnsResolver.Servers))]

	client := dnsResolver.DNSClient

	tries := 1
	start := dnsResolver.clk.Now()
	msgStats.Inc("Calls", 1)
	defer msgStats.TimingDuration("Latency", dnsResolver.clk.Now().Sub(start))
	for {
		msgStats.Inc("Tries", 1)
		ch := make(chan dnsResp, 1)

		go func() {
			rsp, rtt, err := client.Exchange(m, chosenServer)
			msgStats.TimingDuration("SingleTryLatency", rtt)
			ch <- dnsResp{m: rsp, err: err}
		}()
		select {
		case <-ctx.Done():
			msgStats.Inc("Cancels", 1)
			msgStats.Inc("Errors", 1)
			return nil, ctx.Err()
		case r := <-ch:
			if r.err != nil {
				msgStats.Inc("Errors", 1)
				operr, ok := r.err.(*net.OpError)
				isRetryable := ok && operr.Temporary()
				hasRetriesLeft := tries < dnsResolver.maxTries
				if isRetryable && hasRetriesLeft {
					tries++
					continue
				} else if isRetryable && !hasRetriesLeft {
					msgStats.Inc("RanOutOfTries", 1)
				}
			} else {
				msgStats.Inc("Successes", 1)
			}
			return r.m, r.err
		}
	}
}

type dnsResp struct {
	m   *dns.Msg
	err error
}

// LookupTXT sends a DNS query to find all TXT records associated with
// the provided hostname which it returns along with the returned
// DNS authority section.
func (dnsResolver *DNSResolverImpl) LookupTXT(ctx context.Context, hostname string) ([]string, []string, error) {
	var txt []string
	dnsType := dns.TypeTXT
	r, err := dnsResolver.exchangeOne(ctx, hostname, dnsType, dnsResolver.txtStats)
	if err != nil {
		return nil, nil, &dnsError{dnsType, hostname, err, -1}
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, nil, &dnsError{dnsType, hostname, nil, r.Rcode}
	}

	for _, answer := range r.Answer {
		if answer.Header().Rrtype == dnsType {
			if txtRec, ok := answer.(*dns.TXT); ok {
				txt = append(txt, strings.Join(txtRec.Txt, ""))
			}
		}
	}

	authorities := []string{}
	for _, a := range r.Ns {
		authorities = append(authorities, a.String())
	}

	return txt, authorities, err
}

func isPrivateV4(ip net.IP) bool {
	for _, net := range privateNetworks {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

// LookupHost sends a DNS query to find all A records associated with the
// provided hostname. This method assumes that the external resolver will chase
// CNAME/DNAME aliases and return relevant A records.  It will retry requests in
// the case of temporary network errors. It can return net package,
// context.Canceled, and context.DeadlineExceeded errors.
func (dnsResolver *DNSResolverImpl) LookupHost(ctx context.Context, hostname string) ([]net.IP, error) {
	var addrs []net.IP
	dnsType := dns.TypeA
	r, err := dnsResolver.exchangeOne(ctx, hostname, dnsType, dnsResolver.aStats)
	if err != nil {
		return addrs, &dnsError{dnsType, hostname, err, -1}
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, &dnsError{dnsType, hostname, nil, r.Rcode}
	}

	for _, answer := range r.Answer {
		if answer.Header().Rrtype == dnsType {
			if a, ok := answer.(*dns.A); ok && a.A.To4() != nil && (!isPrivateV4(a.A) || dnsResolver.allowRestrictedAddresses) {
				addrs = append(addrs, a.A)
			}
		}
	}

	return addrs, nil
}

// LookupCAA sends a DNS query to find all CAA records associated with
// the provided hostname. If the response code from the resolver is
// SERVFAIL an empty slice of CAA records is returned.
func (dnsResolver *DNSResolverImpl) LookupCAA(ctx context.Context, hostname string) ([]*dns.CAA, error) {
	dnsType := dns.TypeCAA
	r, err := dnsResolver.exchangeOne(ctx, hostname, dnsType, dnsResolver.caaStats)
	if err != nil {
		return nil, &dnsError{dnsType, hostname, err, -1}
	}

	// On resolver validation failure, or other server failures, return empty an
	// set and no error.
	var CAAs []*dns.CAA
	if r.Rcode == dns.RcodeServerFailure {
		return CAAs, nil
	}

	for _, answer := range r.Answer {
		if answer.Header().Rrtype == dnsType {
			if caaR, ok := answer.(*dns.CAA); ok {
				CAAs = append(CAAs, caaR)
			}
		}
	}
	return CAAs, nil
}

// LookupMX sends a DNS query to find a MX record associated hostname and returns the
// record target.
func (dnsResolver *DNSResolverImpl) LookupMX(ctx context.Context, hostname string) ([]string, error) {
	dnsType := dns.TypeMX
	r, err := dnsResolver.exchangeOne(ctx, hostname, dnsType, dnsResolver.mxStats)
	if err != nil {
		return nil, &dnsError{dnsType, hostname, err, -1}
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, &dnsError{dnsType, hostname, nil, r.Rcode}
	}

	var results []string
	for _, answer := range r.Answer {
		if mx, ok := answer.(*dns.MX); ok {
			results = append(results, mx.Mx)
		}
	}

	return results, nil
}
