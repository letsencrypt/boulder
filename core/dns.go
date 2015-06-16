// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
)

// DNSSECError indicates an error caused by DNSSEC failing.
type DNSSECError struct {
}

// Error gives the DNSSEC failure notice.
func (err DNSSECError) Error() string {
	return "DNSSEC validation failure"
}

// DNSResolver represents a resolver system
type DNSResolver struct {
	DNSClient *dns.Client
	Servers   []string
}

// NewDNSResolver constructs a new DNS resolver object that utilizes the
// provided list of DNS servers for resolution.
func NewDNSResolver(dialTimeout time.Duration, servers []string) *DNSResolver {
	dnsClient := new(dns.Client)

	// Set timeout for underlying net.Conn
	dnsClient.DialTimeout = dialTimeout

	return &DNSResolver{DNSClient: dnsClient, Servers: servers}
}

// ExchangeOne performs a single DNS exchange with a randomly chosen server
// out of the server list, returning the response, time, and error (if any)
func (r *DNSResolver) ExchangeOne(m *dns.Msg) (rsp *dns.Msg, rtt time.Duration, err error) {
	if len(r.Servers) < 1 {
		err = fmt.Errorf("Not configured with at least one DNS Server")
		return
	}

	// Randomly pick a server
	chosenServer := r.Servers[rand.Intn(len(r.Servers))]

	return r.DNSClient.Exchange(m, chosenServer)
}

// LookupDNSSEC sends the provided DNS message to a randomly chosen server (see
// ExchangeOne) with DNSSEC enabled. If the lookup fails, this method sends a
// clarification query to determine if it's because DNSSEC was invalid or just
// a run-of-the-mill error. If it's because of DNSSEC, it returns ErrorDNSSEC.
func (dnsResolver *DNSResolver) LookupDNSSEC(m *dns.Msg) (*dns.Msg, time.Duration, error) {
	// Set DNSSEC OK bit
	m.SetEdns0(4096, true)
	r, rtt, err := dnsResolver.ExchangeOne(m)
	if err != nil {
		return r, rtt, err
	}

	if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError && r.Rcode != dns.RcodeNXRrset {
		if r.Rcode == dns.RcodeServerFailure {
			// Re-send query with +cd to see if SERVFAIL was caused by DNSSEC
			// validation failure at the resolver
			m.CheckingDisabled = true
			checkR, _, err := dnsResolver.ExchangeOne(m)
			if err != nil {
				return r, rtt, err
			}

			if checkR.Rcode != dns.RcodeServerFailure {
				// DNSSEC error, so we return the testable object.
				err = DNSSECError{}
				return r, rtt, err
			}
		}
		err = fmt.Errorf("Invalid response code: %d-%s", r.Rcode, dns.RcodeToString[r.Rcode])
		return r, rtt, err
	}

	return r, rtt, err
}

// LookupTXT uses a DNSSEC-enabled query to find all TXT records associated with
// the provided hostname. If the query fails due to DNSSEC, error will be
// set to ErrorDNSSEC.
func (dnsResolver *DNSResolver) LookupTXT(hostname string) ([]string, time.Duration, error) {
	var txt []string

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeTXT)
	r, rtt, err := dnsResolver.LookupDNSSEC(m)

	for _, answer := range r.Answer {
		if answer.Header().Rrtype == dns.TypeTXT {
			txtRec := answer.(*dns.TXT)
			for _, field := range txtRec.Txt {
				txt = append(txt, field)
			}
		}
	}

	return txt, rtt, err
}
