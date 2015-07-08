// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/test"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
)

const dnsLoopbackAddr = "127.0.0.1:4053"

func mockDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	defer w.Close()
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	for _, q := range r.Question {
		switch q.Qtype {
		case dns.TypeSOA:
			record := new(dns.SOA)
			record.Hdr = dns.RR_Header{Name: "letsencrypt.org.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 0}
			record.Ns = "ns.letsencrypt.org."
			record.Mbox = "master.letsencrypt.org."
			record.Serial = 1
			record.Refresh = 1
			record.Retry = 1
			record.Expire = 1
			record.Minttl = 1

			m.Answer = append(m.Answer, record)
			w.WriteMsg(m)
			return
		case dns.TypeA:
			switch q.Name {
			case "cps.letsencrypt.org.":
				record := new(dns.A)
				record.Hdr = dns.RR_Header{Name: "cps.letsencrypt.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
				record.A = net.ParseIP("127.0.0.1")

				m.Answer = append(m.Answer, record)
				w.WriteMsg(m)
				return
			case "sigfail.verteiltesysteme.net.":
				if !r.CheckingDisabled {
					m.Rcode = dns.RcodeServerFailure
				}
				w.WriteMsg(m)
				return
			}
		case dns.TypeCAA:
			if q.Name == "bracewel.net." {
				record := new(dns.CAA)
				record.Hdr = dns.RR_Header{Name: "bracewel.net.", Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 0}
				record.Tag = "issue"
				record.Value = "letsencrypt.org"
				record.Flag = 1

				m.Answer = append(m.Answer, record)
				w.WriteMsg(m)
				return
			}
		}
	}

	w.WriteMsg(m)
	return
}

func serveLoopResolver(stopChan chan bool) chan bool {
	dns.HandleFunc(".", mockDNSQuery)
	server := &dns.Server{Addr: dnsLoopbackAddr, Net: "udp", ReadTimeout: time.Millisecond, WriteTimeout: time.Millisecond}
	waitChan := make(chan bool, 1)
	go func() {
		waitChan <- true
		err := server.ListenAndServe()
		if err != nil {
			fmt.Println(err)
			return
		}
	}()
	go func() {
		<-stopChan
		err := server.Shutdown()
		if err != nil {
			fmt.Println(err)
		}
	}()
	return waitChan
}

func TestMain(m *testing.M) {
	stop := make(chan bool, 1)
	wait := serveLoopResolver(stop)
	<-wait
	ret := m.Run()
	stop <- true
	os.Exit(ret)
}

func TestDNSNoServers(t *testing.T) {
	obj := NewDNSResolverImpl(time.Hour, []string{})

	m := new(dns.Msg)
	_, _, err := obj.ExchangeOne(m)

	test.AssertError(t, err, "No servers")
}

func TestDNSOneServer(t *testing.T) {
	obj := NewDNSResolverImpl(time.Second*10, []string{dnsLoopbackAddr})

	m := new(dns.Msg)
	m.SetQuestion("letsencrypt.org.", dns.TypeSOA)
	_, _, err := obj.ExchangeOne(m)

	test.AssertNotError(t, err, "No message")
}

func TestDNSDuplicateServers(t *testing.T) {
	obj := NewDNSResolverImpl(time.Second*10, []string{dnsLoopbackAddr, dnsLoopbackAddr})

	m := new(dns.Msg)
	m.SetQuestion("letsencrypt.org.", dns.TypeSOA)
	_, _, err := obj.ExchangeOne(m)

	test.AssertNotError(t, err, "No message")
}

func TestDNSLookupsNoServer(t *testing.T) {
	obj := NewDNSResolverImpl(time.Second*10, []string{})

	_, _, err := obj.LookupTXT("letsencrypt.org")
	test.AssertError(t, err, "No servers")

	_, _, err = obj.LookupHost("letsencrypt.org")
	test.AssertError(t, err, "No servers")

	_, err = obj.LookupCNAME("letsencrypt.org")
	test.AssertError(t, err, "No servers")

	_, err = obj.LookupCAA("letsencrypt.org", false)
	test.AssertError(t, err, "No servers")
}

func TestDNSLookupDNSSEC(t *testing.T) {
	goodServer := NewDNSResolverImpl(time.Second*10, []string{dnsLoopbackAddr})

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("sigfail.verteiltesysteme.net"), dns.TypeA)

	_, _, err := goodServer.LookupDNSSEC(m)
	test.AssertError(t, err, "DNSSEC failure")
	_, ok := err.(DNSSECError)
	fmt.Println(err)
	test.Assert(t, ok, "Should have been a DNSSECError")

	m.SetQuestion(dns.Fqdn("sigok.verteiltesysteme.net"), dns.TypeA)

	_, _, err = goodServer.LookupDNSSEC(m)
	test.AssertNotError(t, err, "DNSSEC should have worked")

	badServer := NewDNSResolverImpl(time.Second*10, []string{"127.0.0.1:99"})

	_, _, err = badServer.LookupDNSSEC(m)
	test.AssertError(t, err, "Should have failed")
	_, ok = err.(DNSSECError)
	test.Assert(t, !ok, "Shouldn't have been a DNSSECError")
}

func TestDNSLookupTXT(t *testing.T) {
	obj := NewDNSResolverImpl(time.Second*10, []string{dnsLoopbackAddr})

	a, rtt, err := obj.LookupTXT("letsencrypt.org")

	t.Logf("A: %v RTT %s", a, rtt)
	test.AssertNotError(t, err, "No message")
}

func TestDNSLookupHost(t *testing.T) {
	obj := NewDNSResolverImpl(time.Second*10, []string{dnsLoopbackAddr})

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

func TestDNSLookupCAA(t *testing.T) {
	obj := NewDNSResolverImpl(time.Second*10, []string{dnsLoopbackAddr})

	caas, err := obj.LookupCAA("bracewel.net", false)
	test.AssertNotError(t, err, "CAA lookup failed")
	test.Assert(t, len(caas) > 0, "Should have CAA records")

	caas, err = obj.LookupCAA("nonexistent.letsencrypt.org", false)
	test.AssertNotError(t, err, "CAA lookup failed")
	test.Assert(t, len(caas) == 0, "Shouldn't have CAA records")
}
