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

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
	"github.com/letsencrypt/boulder/metrics"
)

var (
	// Private CIDRs to ignore
	privateNetworks = []net.IPNet{
		// RFC1918
		// 10.0.0.0/8
		net.IPNet{
			IP:   []byte{10, 0, 0, 0},
			Mask: []byte{255, 0, 0, 0},
		},
		// 172.16.0.0/12
		net.IPNet{
			IP:   []byte{172, 16, 0, 0},
			Mask: []byte{255, 240, 0, 0},
		},
		// 192.168.0.0/16
		net.IPNet{
			IP:   []byte{192, 168, 0, 0},
			Mask: []byte{255, 255, 0, 0},
		},
		// RFC5735
		// 127.0.0.0/8
		net.IPNet{
			IP:   []byte{127, 0, 0, 0},
			Mask: []byte{255, 0, 0, 0},
		},
		// RFC1122 Section 3.2.1.3
		// 0.0.0.0/8
		net.IPNet{
			IP:   []byte{0, 0, 0, 0},
			Mask: []byte{255, 0, 0, 0},
		},
		// RFC3927
		// 169.254.0.0/16
		net.IPNet{
			IP:   []byte{169, 254, 0, 0},
			Mask: []byte{255, 255, 0, 0},
		},
		// RFC 5736
		// 192.0.0.0/24
		net.IPNet{
			IP:   []byte{192, 0, 0, 0},
			Mask: []byte{255, 255, 255, 0},
		},
		// RFC 5737
		// 192.0.2.0/24
		net.IPNet{
			IP:   []byte{192, 0, 2, 0},
			Mask: []byte{255, 255, 255, 0},
		},
		// 198.51.100.0/24
		net.IPNet{
			IP:   []byte{192, 51, 100, 0},
			Mask: []byte{255, 255, 255, 0},
		},
		// 203.0.113.0/24
		net.IPNet{
			IP:   []byte{203, 0, 113, 0},
			Mask: []byte{255, 255, 255, 0},
		},
		// RFC 3068
		// 192.88.99.0/24
		net.IPNet{
			IP:   []byte{192, 88, 99, 0},
			Mask: []byte{255, 255, 255, 0},
		},
		// RFC 2544
		// 192.18.0.0/15
		net.IPNet{
			IP:   []byte{192, 18, 0, 0},
			Mask: []byte{255, 254, 0, 0},
		},
		// RFC 3171
		// 224.0.0.0/4
		net.IPNet{
			IP:   []byte{224, 0, 0, 0},
			Mask: []byte{240, 0, 0, 0},
		},
		// RFC 1112
		// 240.0.0.0/4
		net.IPNet{
			IP:   []byte{240, 0, 0, 0},
			Mask: []byte{240, 0, 0, 0},
		},
		// RFC 919 Section 7
		// 255.255.255.255/32
		net.IPNet{
			IP:   []byte{255, 255, 255, 255},
			Mask: []byte{255, 255, 255, 255},
		},
		// RFC 6598
		// 100.64.0.0./10
		net.IPNet{
			IP:   []byte{100, 64, 0, 0},
			Mask: []byte{255, 192, 0, 0},
		},
	}
)

// DNSResolver defines methods used for DNS resolution
type DNSResolver interface {
	LookupTXT(string) ([]string, error)
	LookupHost(string) ([]net.IP, error)
	LookupCAA(string) ([]*dns.CAA, error)
	LookupMX(string) ([]string, error)
}

// DNSResolverImpl represents a client that talks to an external resolver
type DNSResolverImpl struct {
	DNSClient                *dns.Client
	Servers                  []string
	allowRestrictedAddresses bool
	stats                    metrics.Scope
	txtStats                 metrics.Scope
	aStats                   metrics.Scope
	caaStats                 metrics.Scope
	mxStats                  metrics.Scope
}

var _ DNSResolver = &DNSResolverImpl{}

// NewDNSResolverImpl constructs a new DNS resolver object that utilizes the
// provided list of DNS servers for resolution.
func NewDNSResolverImpl(readTimeout time.Duration, servers []string, stats metrics.Scope) *DNSResolverImpl {
	dnsClient := new(dns.Client)

	// Set timeout for underlying net.Conn
	dnsClient.ReadTimeout = readTimeout
	dnsClient.Net = "tcp"

	return &DNSResolverImpl{
		DNSClient:                dnsClient,
		Servers:                  servers,
		allowRestrictedAddresses: false,
		stats:    stats,
		txtStats: stats.NewScope("TXT"),
		aStats:   stats.NewScope("A"),
		caaStats: stats.NewScope("CAA"),
		mxStats:  stats.NewScope("MX"),
	}
}

// NewTestDNSResolverImpl constructs a new DNS resolver object that utilizes the
// provided list of DNS servers for resolution and will allow loopback addresses.
// This constructor should *only* be called from tests (unit or integration).
func NewTestDNSResolverImpl(readTimeout time.Duration, servers []string, stats metrics.Scope) *DNSResolverImpl {
	resolver := NewDNSResolverImpl(readTimeout, servers, stats)
	resolver.allowRestrictedAddresses = true
	return resolver
}

// exchangeOne performs a single DNS exchange with a randomly chosen server
// out of the server list, returning the response, time, and error (if any).
// This method sets the DNSSEC OK bit on the message to true before sending
// it to the resolver in case validation isn't the resolvers default behaviour.
func (dnsResolver *DNSResolverImpl) exchangeOne(hostname string, qtype uint16, msgStats metrics.Scope) (rsp *dns.Msg, err error) {
	m := new(dns.Msg)
	// Set question type
	m.SetQuestion(dns.Fqdn(hostname), qtype)
	// Set DNSSEC OK bit for resolver
	m.SetEdns0(4096, true)

	if len(dnsResolver.Servers) < 1 {
		err = fmt.Errorf("Not configured with at least one DNS Server")
		return
	}

	dnsResolver.stats.Inc("Rate", 1)

	// Randomly pick a server
	chosenServer := dnsResolver.Servers[rand.Intn(len(dnsResolver.Servers))]

	msg, rtt, err := dnsResolver.DNSClient.Exchange(m, chosenServer)
	msgStats.TimingDuration("RTT", rtt)
	if err == nil {
		msgStats.Inc("Successes", 1)
	} else {
		msgStats.Inc("Errors", 1)
	}
	return msg, err
}

// LookupTXT sends a DNS query to find all TXT records associated with
// the provided hostname.
func (dnsResolver *DNSResolverImpl) LookupTXT(hostname string) ([]string, error) {
	var txt []string
	r, err := dnsResolver.exchangeOne(hostname, dns.TypeTXT, dnsResolver.txtStats)
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		err = fmt.Errorf("DNS failure: %d-%s for TXT query", r.Rcode, dns.RcodeToString[r.Rcode])
		return nil, err
	}

	for _, answer := range r.Answer {
		if answer.Header().Rrtype == dns.TypeTXT {
			if txtRec, ok := answer.(*dns.TXT); ok {
				txt = append(txt, strings.Join(txtRec.Txt, ""))
			}
		}
	}

	return txt, err
}

func isPrivateV4(ip net.IP) bool {
	for _, net := range privateNetworks {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

// LookupHost sends a DNS query to find all A records associated with the provided
// hostname. This method assumes that the external resolver will chase CNAME/DNAME
// aliases and return relevant A records.
func (dnsResolver *DNSResolverImpl) LookupHost(hostname string) ([]net.IP, error) {
	var addrs []net.IP

	r, err := dnsResolver.exchangeOne(hostname, dns.TypeA, dnsResolver.aStats)
	if err != nil {
		return addrs, err
	}
	if r.Rcode != dns.RcodeSuccess {
		err = fmt.Errorf("DNS failure: %d-%s for A query", r.Rcode, dns.RcodeToString[r.Rcode])
		return nil, err
	}

	for _, answer := range r.Answer {
		if answer.Header().Rrtype == dns.TypeA {
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
func (dnsResolver *DNSResolverImpl) LookupCAA(hostname string) ([]*dns.CAA, error) {
	r, err := dnsResolver.exchangeOne(hostname, dns.TypeCAA, dnsResolver.caaStats)
	if err != nil {
		return nil, err
	}

	// On resolver validation failure, or other server failures, return empty an
	// set and no error.
	var CAAs []*dns.CAA
	if r.Rcode == dns.RcodeServerFailure {
		return CAAs, nil
	}

	for _, answer := range r.Answer {
		if answer.Header().Rrtype == dns.TypeCAA {
			if caaR, ok := answer.(*dns.CAA); ok {
				CAAs = append(CAAs, caaR)
			}
		}
	}
	return CAAs, nil
}

// LookupMX sends a DNS query to find a MX record associated hostname and returns the
// record target.
func (dnsResolver *DNSResolverImpl) LookupMX(hostname string) ([]string, error) {
	r, err := dnsResolver.exchangeOne(hostname, dns.TypeMX, dnsResolver.mxStats)
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		err = fmt.Errorf("DNS failure: %d-%s for MX query", r.Rcode, dns.RcodeToString[r.Rcode])
		return nil, err
	}

	var results []string
	for _, answer := range r.Answer {
		if mx, ok := answer.(*dns.MX); ok {
			results = append(results, mx.Mx)
		}
	}

	return results, nil
}
