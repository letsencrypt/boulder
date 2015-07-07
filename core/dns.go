// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
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
func (dnsResolver *DNSResolverImpl) ExchangeOne(m *dns.Msg) (rsp *dns.Msg, rtt time.Duration, err error) {
	if len(dnsResolver.Servers) < 1 {
		err = fmt.Errorf("Not configured with at least one DNS Server")
		return
	}

	// Randomly pick a server
	chosenServer := dnsResolver.Servers[rand.Intn(len(dnsResolver.Servers))]

	return dnsResolver.DNSClient.Exchange(m, chosenServer)
}

// LookupDNSSEC sends the provided DNS message to a randomly chosen server (see
// ExchangeOne) with DNSSEC enabled. If the lookup fails, this method sends a
// clarification query to determine if it's because DNSSEC was invalid or just
// a run-of-the-mill error. If it's because of DNSSEC, it returns ErrorDNSSEC.
func (dnsResolver *DNSResolverImpl) LookupDNSSEC(m *dns.Msg) (*dns.Msg, time.Duration, error) {
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
func (dnsResolver *DNSResolverImpl) LookupTXT(hostname string) ([]string, time.Duration, error) {
	var txt []string

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeTXT)
	r, rtt, err := dnsResolver.LookupDNSSEC(m)

	if err != nil {
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

// LookupHost uses a DNSSEC-enabled query to find all A/AAAA records associated with
// the provided hostname. If the query fails due to DNSSEC, error will be
// set to ErrorDNSSEC.
func (dnsResolver *DNSResolverImpl) LookupHost(hostname string) ([]net.IP, time.Duration, error) {
	var addrs []net.IP
	var answers []dns.RR

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
	r, aRtt, err := dnsResolver.LookupDNSSEC(m)
	if err != nil {
		return addrs, aRtt, err
	}
	answers = append(answers, r.Answer...)

	m.SetQuestion(dns.Fqdn(hostname), dns.TypeAAAA)
	r, aaaaRtt, err := dnsResolver.LookupDNSSEC(m)
	if err != nil {
		return addrs, aRtt + aaaaRtt, err
	}
	answers = append(answers, r.Answer...)

	for _, answer := range answers {
		if answer.Header().Rrtype == dns.TypeA {
			a := answer.(*dns.A)
			addrs = append(addrs, a.A)
		} else if answer.Header().Rrtype == dns.TypeAAAA {
			aaaa := answer.(*dns.AAAA)
			addrs = append(addrs, aaaa.AAAA)
		}
	}

	return addrs, aRtt + aaaaRtt, nil
}

// LookupCNAME uses a DNSSEC-enabled query to  records for domain and returns either
// the target, "", or a if the query fails due to DNSSEC, error will be set to
// ErrorDNSSEC.
func (dnsResolver *DNSResolverImpl) LookupCNAME(domain string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCNAME)

	r, _, err := dnsResolver.LookupDNSSEC(m)
	if err != nil {
		return "", err
	}

	for _, answer := range r.Answer {
		if cname, ok := answer.(*dns.CNAME); ok {
			return cname.Target, nil
		}
	}

	return "", nil
}

// LookupCAA uses a DNSSEC-enabled query to find all CAA records associated with
// the provided hostname. If the query fails due to DNSSEC, error will be
// set to ErrorDNSSEC.
func (dnsResolver *DNSResolverImpl) LookupCAA(domain string, alias bool) ([]*dns.CAA, error) {
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

	r, _, err := dnsResolver.LookupDNSSEC(m)
	if err != nil {
		return nil, err
	}

	var CAAs []*dns.CAA
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

	return CAAs, nil
}
