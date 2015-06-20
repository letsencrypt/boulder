// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"testing"
	"time"

	"github.com/letsencrypt/boulder/test"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
)

func TestDNSNoServers(t *testing.T) {
	obj := NewDNSResolver(time.Hour, []string{})

	m := new(dns.Msg)
	_, _, err := obj.ExchangeOne(m)

	test.AssertError(t, err, "No servers")
}

func TestDNSOneServer(t *testing.T) {
	obj := NewDNSResolver(time.Second*10, []string{"8.8.8.8:53"})

	m := new(dns.Msg)
	m.SetQuestion("letsencrypt.org.", dns.TypeSOA)
	_, _, err := obj.ExchangeOne(m)

	test.AssertNotError(t, err, "No message")
}

func TestDNSDuplicateServers(t *testing.T) {
	obj := NewDNSResolver(time.Second*10, []string{"8.8.8.8:53", "8.8.8.8:53"})

	m := new(dns.Msg)
	m.SetQuestion("letsencrypt.org.", dns.TypeSOA)
	_, _, err := obj.ExchangeOne(m)

	test.AssertNotError(t, err, "No message")
}

func TestDNSLookupTXT(t *testing.T) {
	obj := NewDNSResolver(time.Second*10, []string{"8.8.8.8:53", "8.8.8.8:53"})

	a, rtt, err := obj.LookupTXT("letsencrypt.org")

	t.Logf("A: %v RTT %s", a, rtt)
	test.AssertNotError(t, err, "No message")
}

func TestDNSLookupTXTNoServer(t *testing.T) {
	obj := NewDNSResolver(time.Second*10, []string{})

	_, _, err := obj.LookupTXT("letsencrypt.org")
	test.AssertError(t, err, "No servers")
}

func TestDNSSEC(t *testing.T) {
	goodServer := NewDNSResolver(time.Second*10, []string{"8.8.8.8:53"})

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("sigfail.verteiltesysteme.net"), dns.TypeA)

	_, _, err := goodServer.LookupDNSSEC(m)
	test.AssertError(t, err, "DNSSEC failure")
	_, ok := err.(DNSSECError)
	test.Assert(t, ok, "Should have been a DNSSECError")

	m.SetQuestion(dns.Fqdn("sigok.verteiltesysteme.net"), dns.TypeA)

	_, _, err = goodServer.LookupDNSSEC(m)
	test.AssertNotError(t, err, "DNSSEC should have worked")

	badServer := NewDNSResolver(time.Second*10, []string{"127.0.0.1:99"})

	_, _, err = badServer.LookupDNSSEC(m)
	test.AssertError(t, err, "Should have failed")
	_, ok = err.(DNSSECError)
	test.Assert(t, !ok, "Shouldn't have been a DNSSECError")

}

func TestDNSLookupHost(t *testing.T) {
	obj := NewDNSResolver(time.Second*10, []string{"8.8.8.8:53"})

	ip, _, err := obj.LookupHost("sigfail.verteiltesysteme.net")
	t.Logf("sigfail.verteiltesysteme.net - IP: %s, Err: %s", ip, err)
	test.AssertError(t, err, "DNSSEC failure")
	test.Assert(t, len(ip) == 0, "Should not have IPs")

	ip, _, err = obj.LookupHost("nonexistent.letsencrypt.org")
	t.Logf("nonexistent.letsencrypt.org - IP: %s, Err: %s", ip, err)
	test.AssertNotError(t, err, "Not an error to not exist")
	test.Assert(t, len(ip) == 0, "Should not have IPs")

	ip, _, err = obj.LookupHost("cps.letsencrypt.org")
	t.Logf("cps.letsencrypt.org - IP: %s, Err: %s", ip, err)
	test.AssertNotError(t, err, "Not an error to be a CNAME")
	test.Assert(t, len(ip) > 0, "Should have IPs")
}
