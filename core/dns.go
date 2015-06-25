// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"errors"
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

// DNSResolverImpl represents a resolver system
type DNSResolverImpl struct {
	DNSClient *dns.Client
	Servers   []string
}

// NewDNSResolverImpl constructs a new DNS resolver object that utilizes the
// provided list of DNS servers for resolution.
func NewDNSResolverImpl(dialTimeout time.Duration, servers []string) *DNSResolverImpl {
	dnsClient := new(dns.Client)

	// Set timeout for underlying net.Conn
	dnsClient.DialTimeout = dialTimeout

	return &DNSResolverImpl{DNSClient: dnsClient, Servers: servers}
}

// ExchangeOne performs a single DNS exchange with a randomly chosen server
// out of the server list, returning the response, time, and error (if any)
func (dnsResolver *DNSResolver) ExchangeOne(m *dns.Msg) (rsp *dns.Msg, rtt time.Duration, err error) {
	// Set DNSSEC OK bit
	m.SetEdns0(4096, true)

	if len(dnsResolver.Servers) < 1 {
		err = fmt.Errorf("Not configured with at least one DNS Server")
		return
	}

	// Randomly pick a server
	chosenServer := dnsResolver.Servers[rand.Intn(len(dnsResolver.Servers))]

	return dnsResolver.DNSClient.Exchange(m, chosenServer)
}

// LookupTXT sends a DNS query to find all TXT records associated with
// the provided hostname.
func (dnsResolver *DNSResolver) LookupTXT(hostname string) ([]string, time.Duration, error) {
	var txt []string

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeTXT)
	r, rtt, err := dnsResolver.ExchangeOne(m)

	if err != nil {
		return nil, 0, err
	}

	if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError && r.Rcode != dns.RcodeNXRrset {
		err = fmt.Errorf("Failure at resolver: %d-%s for TXT query", r.Rcode, dns.RcodeToString[r.Rcode])
		return nil, 0, err
	}

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

// LookupCNAME sends a DNS query to find a CNAME record associated domain and returns the
// record target.
func (dnsResolver *DNSResolver) LookupCNAME(domain string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCNAME)

	r, _, err := dnsResolver.ExchangeOne(m)
	if err != nil {
		return "", err
	}

	if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError && r.Rcode != dns.RcodeNXRrset {
		err = fmt.Errorf("Failure at resolver: %d-%s for CNAME query", r.Rcode, dns.RcodeToString[r.Rcode])
		return "", err
	}

	for _, answer := range r.Answer {
		if cname, ok := answer.(*dns.CNAME); ok {
			return cname.Target, nil
		}
	}

	return "", nil
}

// LookupCAA sends a DNS query to find all CAA records associated with
// the provided hostname. If the response code from the resolver is SERVFAIL
// an empty slice of CAA records is returned.
func (dnsResolver *DNSResolver) LookupCAA(domain string, alias bool) ([]*dns.CAA, error) {
	if alias {
		// Check if there is a CNAME record for domain
		canonName, err := dnsResolver.LookupCNAME(domain)
		if err != nil {
			return nil, err
		}
		if canonName == "" || canonName == domain {
			return []*dns.CAA{}, nil
		}
		domain = canonName
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCAA)

	r, _, err := dnsResolver.ExchangeOne(m)
	if err != nil {
		return nil, err
	}

	var CAAs []*dns.CAA
	// XXX: On resolver validation failure, or other server failures, return empty
	//      set and no error.
	if r.Rcode != dns.RcodeServerFailure {
		for _, answer := range r.Answer {
			if answer.Header().Rrtype == dns.TypeCAA {
				caaR, ok := answer.(*dns.CAA)
				if !ok {
					err = errors.New("Badly formatted record")
					return nil, err
				}
				CAAs = append(CAAs, caaR)
			}
		}
	}

	return CAAs, nil
}
