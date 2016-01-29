// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bdns

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/golang.org/x/net/context"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
)

const dnsLoopbackAddr = "127.0.0.1:4053"

func mockDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	appendAnswer := func(rr dns.RR) {
		m.Answer = append(m.Answer, rr)
	}
	for _, q := range r.Question {
		q.Name = strings.ToLower(q.Name)
		if q.Name == "servfail.com." {
			m.Rcode = dns.RcodeServerFailure
			break
		}
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
			appendAnswer(record)
		case dns.TypeAAAA:
			if q.Name == "v6.letsencrypt.org." {
				record := new(dns.AAAA)
				record.Hdr = dns.RR_Header{Name: "v6.letsencrypt.org.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0}
				record.AAAA = net.ParseIP("::1")
				appendAnswer(record)
			}
		case dns.TypeA:
			if q.Name == "cps.letsencrypt.org." {
				record := new(dns.A)
				record.Hdr = dns.RR_Header{Name: "cps.letsencrypt.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
				record.A = net.ParseIP("127.0.0.1")
				appendAnswer(record)
			}
			if q.Name == "nxdomain.letsencrypt.org." {
				m.SetRcode(r, dns.RcodeNameError)
			}
		case dns.TypeCNAME:
			if q.Name == "cname.letsencrypt.org." {
				record := new(dns.CNAME)
				record.Hdr = dns.RR_Header{Name: "cname.letsencrypt.org.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30}
				record.Target = "cps.letsencrypt.org."
				appendAnswer(record)
			}
			if q.Name == "cname.example.com." {
				record := new(dns.CNAME)
				record.Hdr = dns.RR_Header{Name: "cname.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30}
				record.Target = "CAA.example.com."
				appendAnswer(record)
			}
		case dns.TypeDNAME:
			if q.Name == "dname.letsencrypt.org." {
				record := new(dns.DNAME)
				record.Hdr = dns.RR_Header{Name: "dname.letsencrypt.org.", Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 30}
				record.Target = "cps.letsencrypt.org."
				appendAnswer(record)
			}
		case dns.TypeCAA:
			if q.Name == "bracewel.net." || q.Name == "caa.example.com." {
				record := new(dns.CAA)
				record.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 0}
				record.Tag = "issue"
				record.Value = "letsencrypt.org"
				record.Flag = 1
				appendAnswer(record)
			}
			if q.Name == "cname.example.com." {
				record := new(dns.CAA)
				record.Hdr = dns.RR_Header{Name: "caa.example.com.", Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 0}
				record.Tag = "issue"
				record.Value = "letsencrypt.org"
				record.Flag = 1
				appendAnswer(record)
			}
		case dns.TypeTXT:
			if q.Name == "split-txt.letsencrypt.org." {
				record := new(dns.TXT)
				record.Hdr = dns.RR_Header{Name: "split-txt.letsencrypt.org.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}
				record.Txt = []string{"a", "b", "c"}
				appendAnswer(record)
			} else {
				auth := new(dns.SOA)
				auth.Hdr = dns.RR_Header{Name: "letsencrypt.org.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 0}
				auth.Ns = "ns.letsencrypt.org."
				auth.Mbox = "master.letsencrypt.org."
				auth.Serial = 1
				auth.Refresh = 1
				auth.Retry = 1
				auth.Expire = 1
				auth.Minttl = 1
				m.Ns = append(m.Ns, auth)
			}
			if q.Name == "nxdomain.letsencrypt.org." {
				m.SetRcode(r, dns.RcodeNameError)
			}
		}
	}

	w.WriteMsg(m)
	return
}

func serveLoopResolver(stopChan chan bool) chan bool {
	dns.HandleFunc(".", mockDNSQuery)
	server := &dns.Server{Addr: dnsLoopbackAddr, Net: "tcp", ReadTimeout: time.Millisecond, WriteTimeout: time.Millisecond}
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

func newTestStats() metrics.Scope {
	c, _ := statsd.NewNoopClient()
	return metrics.NewStatsdScope(c, "fakesvc")
}

var testStats = newTestStats()

func TestDNSNoServers(t *testing.T) {
	obj := NewTestDNSResolverImpl(time.Hour, []string{}, testStats, clock.NewFake(), 1)

	_, err := obj.LookupHost(context.Background(), "letsencrypt.org")

	test.AssertError(t, err, "No servers")
}

func TestDNSOneServer(t *testing.T) {
	obj := NewTestDNSResolverImpl(time.Second*10, []string{dnsLoopbackAddr}, testStats, clock.NewFake(), 1)

	_, err := obj.LookupHost(context.Background(), "letsencrypt.org")

	test.AssertNotError(t, err, "No message")
}

func TestDNSDuplicateServers(t *testing.T) {
	obj := NewTestDNSResolverImpl(time.Second*10, []string{dnsLoopbackAddr, dnsLoopbackAddr}, testStats, clock.NewFake(), 1)

	_, err := obj.LookupHost(context.Background(), "letsencrypt.org")

	test.AssertNotError(t, err, "No message")
}

func TestDNSLookupsNoServer(t *testing.T) {
	obj := NewTestDNSResolverImpl(time.Second*10, []string{}, testStats, clock.NewFake(), 1)

	_, _, err := obj.LookupTXT(context.Background(), "letsencrypt.org")
	test.AssertError(t, err, "No servers")

	_, err = obj.LookupHost(context.Background(), "letsencrypt.org")
	test.AssertError(t, err, "No servers")

	_, err = obj.LookupCAA(context.Background(), "letsencrypt.org")
	test.AssertError(t, err, "No servers")
}

func TestDNSServFail(t *testing.T) {
	obj := NewTestDNSResolverImpl(time.Second*10, []string{dnsLoopbackAddr}, testStats, clock.NewFake(), 1)
	bad := "servfail.com"

	_, _, err := obj.LookupTXT(context.Background(), bad)
	test.AssertError(t, err, "LookupTXT didn't return an error")

	_, err = obj.LookupHost(context.Background(), bad)
	test.AssertError(t, err, "LookupHost didn't return an error")

	// CAA lookup ignores validation failures from the resolver for now
	// and returns an empty list of CAA records.
	emptyCaa, err := obj.LookupCAA(context.Background(), bad)
	test.Assert(t, len(emptyCaa) == 0, "Query returned non-empty list of CAA records")
	test.AssertNotError(t, err, "LookupCAA returned an error")
}

func TestDNSLookupTXT(t *testing.T) {
	obj := NewTestDNSResolverImpl(time.Second*10, []string{dnsLoopbackAddr}, testStats, clock.NewFake(), 1)

	a, _, err := obj.LookupTXT(context.Background(), "letsencrypt.org")
	t.Logf("A: %v", a)
	test.AssertNotError(t, err, "No message")

	a, _, err = obj.LookupTXT(context.Background(), "split-txt.letsencrypt.org")
	t.Logf("A: %v ", a)
	test.AssertNotError(t, err, "No message")
	test.AssertEquals(t, len(a), 1)
	test.AssertEquals(t, a[0], "abc")
}

func TestDNSLookupHost(t *testing.T) {
	obj := NewTestDNSResolverImpl(time.Second*10, []string{dnsLoopbackAddr}, testStats, clock.NewFake(), 1)

	ip, err := obj.LookupHost(context.Background(), "servfail.com")
	t.Logf("servfail.com - IP: %s, Err: %s", ip, err)
	test.AssertError(t, err, "Server failure")
	test.Assert(t, len(ip) == 0, "Should not have IPs")

	ip, err = obj.LookupHost(context.Background(), "nonexistent.letsencrypt.org")
	t.Logf("nonexistent.letsencrypt.org - IP: %s, Err: %s", ip, err)
	test.AssertNotError(t, err, "Not an error to not exist")
	test.Assert(t, len(ip) == 0, "Should not have IPs")

	// Single IPv4 address
	ip, err = obj.LookupHost(context.Background(), "cps.letsencrypt.org")
	t.Logf("cps.letsencrypt.org - IP: %s, Err: %s", ip, err)
	test.AssertNotError(t, err, "Not an error to exist")
	test.Assert(t, len(ip) == 1, "Should have IP")
	ip, err = obj.LookupHost(context.Background(), "cps.letsencrypt.org")
	t.Logf("cps.letsencrypt.org - IP: %s, Err: %s", ip, err)
	test.AssertNotError(t, err, "Not an error to exist")
	test.Assert(t, len(ip) == 1, "Should have IP")

	// No IPv6
	ip, err = obj.LookupHost(context.Background(), "v6.letsencrypt.org")
	t.Logf("v6.letsencrypt.org - IP: %s, Err: %s", ip, err)
	test.AssertNotError(t, err, "Not an error to exist")
	test.Assert(t, len(ip) == 0, "Should not have IPs")
}

func TestDNSNXDOMAIN(t *testing.T) {
	obj := NewTestDNSResolverImpl(time.Second*10, []string{dnsLoopbackAddr}, testStats, clock.NewFake(), 1)

	hostname := "nxdomain.letsencrypt.org"
	_, err := obj.LookupHost(context.Background(), hostname)
	expected := dnsError{dns.TypeA, hostname, nil, dns.RcodeNameError}
	if err, ok := err.(*dnsError); !ok || *err != expected {
		t.Errorf("Looking up %s, got %#v, expected %#v", hostname, err, expected)
	}

	_, _, err = obj.LookupTXT(context.Background(), hostname)
	expected.recordType = dns.TypeTXT
	if err, ok := err.(*dnsError); !ok || *err != expected {
		t.Errorf("Looking up %s, got %#v, expected %#v", hostname, err, expected)
	}
}

func TestDNSLookupCAA(t *testing.T) {
	obj := NewTestDNSResolverImpl(time.Second*10, []string{dnsLoopbackAddr}, testStats, clock.NewFake(), 1)

	caas, err := obj.LookupCAA(context.Background(), "bracewel.net")
	test.AssertNotError(t, err, "CAA lookup failed")
	test.Assert(t, len(caas) > 0, "Should have CAA records")

	caas, err = obj.LookupCAA(context.Background(), "nonexistent.letsencrypt.org")
	test.AssertNotError(t, err, "CAA lookup failed")
	test.Assert(t, len(caas) == 0, "Shouldn't have CAA records")

	caas, err = obj.LookupCAA(context.Background(), "cname.example.com")
	test.AssertNotError(t, err, "CAA lookup failed")
	test.Assert(t, len(caas) > 0, "Should follow CNAME to find CAA")
}

func TestDNSTXTAuthorities(t *testing.T) {
	obj := NewTestDNSResolverImpl(time.Second*10, []string{dnsLoopbackAddr}, testStats, clock.NewFake(), 1)

	_, auths, err := obj.LookupTXT(context.Background(), "letsencrypt.org")

	test.AssertNotError(t, err, "TXT lookup failed")
	test.AssertEquals(t, len(auths), 1)
	test.AssertEquals(t, auths[0], "letsencrypt.org.	0	IN	SOA	ns.letsencrypt.org. master.letsencrypt.org. 1 1 1 1 1")
}

type testExchanger struct {
	sync.Mutex
	count int
	errs  []error
}

var errTooManyRequests = errors.New("too many requests")

func (te *testExchanger) Exchange(m *dns.Msg, a string) (*dns.Msg, time.Duration, error) {
	te.Lock()
	defer te.Unlock()
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
	}
	if len(te.errs) <= te.count {
		return nil, 0, errTooManyRequests
	}
	err := te.errs[te.count]
	te.count++

	return msg, 2 * time.Millisecond, err
}

func TestRetry(t *testing.T) {
	isTempErr := &net.OpError{Op: "read", Err: tempError(true)}
	nonTempErr := &net.OpError{Op: "read", Err: tempError(false)}
	servFailError := errors.New("DNS problem: server failure at resolver looking up TXT for example.com")
	netError := errors.New("DNS problem: networking error looking up TXT for example.com")
	type testCase struct {
		maxTries      int
		te            *testExchanger
		expected      error
		expectedCount int
	}
	tests := []*testCase{
		// The success on first try case
		{
			maxTries: 3,
			te: &testExchanger{
				errs: []error{nil},
			},
			expected:      nil,
			expectedCount: 1,
		},
		// Immediate non-OpError, error returns immediately
		{
			maxTries: 3,
			te: &testExchanger{
				errs: []error{errors.New("nope")},
			},
			expected:      servFailError,
			expectedCount: 1,
		},
		// Temporary err, then non-OpError stops at two tries
		{
			maxTries: 3,
			te: &testExchanger{
				errs: []error{isTempErr, errors.New("nope")},
			},
			expected:      servFailError,
			expectedCount: 2,
		},
		// Temporary error given always
		{
			maxTries: 3,
			te: &testExchanger{
				errs: []error{
					isTempErr,
					isTempErr,
					isTempErr,
				},
			},
			expected:      netError,
			expectedCount: 3,
		},
		// Even with maxTries at 0, we should still let a single request go
		// through
		{
			maxTries: 0,
			te: &testExchanger{
				errs: []error{nil},
			},
			expected:      nil,
			expectedCount: 1,
		},
		// Temporary error given just once causes two tries
		{
			maxTries: 3,
			te: &testExchanger{
				errs: []error{
					isTempErr,
					nil,
				},
			},
			expected:      nil,
			expectedCount: 2,
		},
		// Temporary error given twice causes three tries
		{
			maxTries: 3,
			te: &testExchanger{
				errs: []error{
					isTempErr,
					isTempErr,
					nil,
				},
			},
			expected:      nil,
			expectedCount: 3,
		},
		// Temporary error given thrice causes three tries and fails
		{
			maxTries: 3,
			te: &testExchanger{
				errs: []error{
					isTempErr,
					isTempErr,
					isTempErr,
				},
			},
			expected:      netError,
			expectedCount: 3,
		},
		// temporary then non-Temporary error causes two retries
		{
			maxTries: 3,
			te: &testExchanger{
				errs: []error{
					isTempErr,
					nonTempErr,
				},
			},
			expected:      netError,
			expectedCount: 2,
		},
	}

	for i, tc := range tests {
		dr := NewTestDNSResolverImpl(time.Second*10, []string{dnsLoopbackAddr}, testStats, clock.NewFake(), tc.maxTries)

		dr.DNSClient = tc.te
		_, _, err := dr.LookupTXT(context.Background(), "example.com")
		if err == errTooManyRequests {
			t.Errorf("#%d, sent more requests than the test case handles", i)
		}
		expectedErr := tc.expected
		if (expectedErr == nil && err != nil) ||
			(expectedErr != nil && err == nil) ||
			(expectedErr != nil && expectedErr.Error() != err.Error()) {
			t.Errorf("#%d, error, expected %v, got %v", i, expectedErr, err)
		}
		if tc.expectedCount != tc.te.count {
			t.Errorf("#%d, error, expectedCount %v, got %v", i, tc.expectedCount, tc.te.count)
		}
	}

	dr := NewTestDNSResolverImpl(time.Second*10, []string{dnsLoopbackAddr}, testStats, clock.NewFake(), 3)
	dr.DNSClient = &testExchanger{errs: []error{isTempErr, isTempErr, nil}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := dr.LookupTXT(ctx, "example.com")
	if err == nil ||
		err.Error() != "DNS problem: query timed out looking up TXT for example.com" {
		t.Errorf("expected %s, got %s", context.Canceled, err)
	}

	dr.DNSClient = &testExchanger{errs: []error{isTempErr, isTempErr, nil}}
	ctx, _ = context.WithTimeout(context.Background(), -10*time.Hour)
	_, _, err = dr.LookupTXT(ctx, "example.com")
	if err == nil ||
		err.Error() != "DNS problem: query timed out looking up TXT for example.com" {
		t.Errorf("expected %s, got %s", context.DeadlineExceeded, err)
	}

	dr.DNSClient = &testExchanger{errs: []error{isTempErr, isTempErr, nil}}
	ctx, deadlineCancel := context.WithTimeout(context.Background(), -10*time.Hour)
	deadlineCancel()
	_, _, err = dr.LookupTXT(ctx, "example.com")
	if err == nil ||
		err.Error() != "DNS problem: query timed out looking up TXT for example.com" {
		t.Errorf("expected %s, got %s", context.DeadlineExceeded, err)
	}
}

type tempError bool

func (t tempError) Temporary() bool { return bool(t) }
func (t tempError) Error() string   { return fmt.Sprintf("Temporary: %t", t) }
