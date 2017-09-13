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

	"golang.org/x/net/context"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
	"github.com/miekg/dns"
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
		if q.Name == "servfail.com." || q.Name == "servfailexception.example.com" {
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
			if q.Name == "dualstack.letsencrypt.org." {
				record := new(dns.AAAA)
				record.Hdr = dns.RR_Header{Name: "dualstack.letsencrypt.org.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0}
				record.AAAA = net.ParseIP("::1")
				appendAnswer(record)
			}
			if q.Name == "v4error.letsencrypt.org." {
				record := new(dns.AAAA)
				record.Hdr = dns.RR_Header{Name: "v4error.letsencrypt.org.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0}
				record.AAAA = net.ParseIP("::1")
				appendAnswer(record)
			}
			if q.Name == "v6error.letsencrypt.org." {
				m.SetRcode(r, dns.RcodeNotImplemented)
			}
			if q.Name == "nxdomain.letsencrypt.org." {
				m.SetRcode(r, dns.RcodeNameError)
			}
			if q.Name == "dualstackerror.letsencrypt.org." {
				m.SetRcode(r, dns.RcodeNotImplemented)
			}
		case dns.TypeA:
			if q.Name == "cps.letsencrypt.org." {
				record := new(dns.A)
				record.Hdr = dns.RR_Header{Name: "cps.letsencrypt.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
				record.A = net.ParseIP("127.0.0.1")
				appendAnswer(record)
			}
			if q.Name == "dualstack.letsencrypt.org." {
				record := new(dns.A)
				record.Hdr = dns.RR_Header{Name: "dualstack.letsencrypt.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
				record.A = net.ParseIP("127.0.0.1")
				appendAnswer(record)
			}
			if q.Name == "v6error.letsencrypt.org." {
				record := new(dns.A)
				record.Hdr = dns.RR_Header{Name: "dualstack.letsencrypt.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
				record.A = net.ParseIP("127.0.0.1")
				appendAnswer(record)
			}
			if q.Name == "v4error.letsencrypt.org." {
				m.SetRcode(r, dns.RcodeNotImplemented)
			}
			if q.Name == "nxdomain.letsencrypt.org." {
				m.SetRcode(r, dns.RcodeNameError)
			}
			if q.Name == "dualstackerror.letsencrypt.org." {
				m.SetRcode(r, dns.RcodeRefused)
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
			if q.Name == "dname.example.com." {
				appendAnswer(&dns.DNAME{
					Hdr:    dns.RR_Header{Name: "dname.example.com.", Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 0},
					Target: "dname.example.net.",
				})
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

	err := w.WriteMsg(m)
	if err != nil {
		panic(err) // running tests, so panic is OK
	}
	return
}

func serveLoopResolver(stopChan chan bool) {
	dns.HandleFunc(".", mockDNSQuery)
	server := &dns.Server{Addr: dnsLoopbackAddr, Net: "tcp", ReadTimeout: time.Second, WriteTimeout: time.Second}
	go func() {
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
}

func pollServer() {
	backoff := time.Duration(200 * time.Millisecond)
	ctx, _ := context.WithTimeout(context.Background(), time.Duration(5*time.Second))
	ticker := time.NewTicker(backoff)

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "Timeout reached while testing for the dns server to come up")
			os.Exit(1)
		case <-ticker.C:
			conn, _ := dns.DialTimeout("tcp", dnsLoopbackAddr, backoff)
			if conn != nil {
				_ = conn.Close()
				return
			}
		}
	}
}

func TestMain(m *testing.M) {
	stop := make(chan bool, 1)
	serveLoopResolver(stop)
	pollServer()
	ret := m.Run()
	stop <- true
	os.Exit(ret)
}

func newTestStats() metrics.Scope {
	return metrics.NewNoopScope()
}

var testStats = newTestStats()

func TestDNSNoServers(t *testing.T) {
	obj := NewTestDNSClientImpl(time.Hour, []string{}, testStats, clock.NewFake(), 1)

	_, err := obj.LookupHost(context.Background(), "letsencrypt.org")

	test.AssertError(t, err, "No servers")
}

func TestDNSOneServer(t *testing.T) {
	obj := NewTestDNSClientImpl(time.Second*10, []string{dnsLoopbackAddr}, testStats, clock.NewFake(), 1)

	_, err := obj.LookupHost(context.Background(), "letsencrypt.org")

	test.AssertNotError(t, err, "No message")
}

func TestDNSDuplicateServers(t *testing.T) {
	obj := NewTestDNSClientImpl(time.Second*10, []string{dnsLoopbackAddr, dnsLoopbackAddr}, testStats, clock.NewFake(), 1)

	_, err := obj.LookupHost(context.Background(), "letsencrypt.org")

	test.AssertNotError(t, err, "No message")
}

func TestDNSLookupsNoServer(t *testing.T) {
	obj := NewTestDNSClientImpl(time.Second*10, []string{}, testStats, clock.NewFake(), 1)

	_, _, err := obj.LookupTXT(context.Background(), "letsencrypt.org")
	test.AssertError(t, err, "No servers")

	_, err = obj.LookupHost(context.Background(), "letsencrypt.org")
	test.AssertError(t, err, "No servers")

	_, _, err = obj.LookupCAA(context.Background(), "letsencrypt.org")
	test.AssertError(t, err, "No servers")
}

func TestDNSServFail(t *testing.T) {
	obj := NewTestDNSClientImpl(time.Second*10, []string{dnsLoopbackAddr}, testStats, clock.NewFake(), 1)
	bad := "servfail.com"

	_, _, err := obj.LookupTXT(context.Background(), bad)
	test.AssertError(t, err, "LookupTXT didn't return an error")

	_, err = obj.LookupHost(context.Background(), bad)
	test.AssertError(t, err, "LookupHost didn't return an error")

	// CAA lookup ignores validation failures from the resolver for now
	// and returns an empty list of CAA records.
	emptyCaa, _, err := obj.LookupCAA(context.Background(), bad)
	test.Assert(t, len(emptyCaa) == 0, "Query returned non-empty list of CAA records")
	test.AssertNotError(t, err, "LookupCAA returned an error")

	// When we turn on enforceCAASERVFAIL, such lookups should fail.
	obj.caaSERVFAILExceptions = map[string]bool{"servfailexception.example.com": true}
	emptyCaa, _, err = obj.LookupCAA(context.Background(), bad)
	test.Assert(t, len(emptyCaa) == 0, "Query returned non-empty list of CAA records")
	test.AssertError(t, err, "LookupCAA should have returned an error")

	// Unless they are on the exception list
	emptyCaa, _, err = obj.LookupCAA(context.Background(), "servfailexception.example.com")
	test.Assert(t, len(emptyCaa) == 0, "Query returned non-empty list of CAA records")
	test.AssertNotError(t, err, "LookupCAA for servfail exception returned an error")
}

func TestDNSLookupTXT(t *testing.T) {
	obj := NewTestDNSClientImpl(time.Second*10, []string{dnsLoopbackAddr}, testStats, clock.NewFake(), 1)

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
	obj := NewTestDNSClientImpl(time.Second*10, []string{dnsLoopbackAddr}, testStats, clock.NewFake(), 1)

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

	// Single IPv6 address
	ip, err = obj.LookupHost(context.Background(), "v6.letsencrypt.org")
	t.Logf("v6.letsencrypt.org - IP: %s, Err: %s", ip, err)
	test.AssertNotError(t, err, "Not an error to exist")
	test.Assert(t, len(ip) == 1, "Should not have IPs")

	// Both IPv6 and IPv4 address
	ip, err = obj.LookupHost(context.Background(), "dualstack.letsencrypt.org")
	t.Logf("dualstack.letsencrypt.org - IP: %s, Err: %s", ip, err)
	test.AssertNotError(t, err, "Not an error to exist")
	test.Assert(t, len(ip) == 2, "Should have 2 IPs")
	expected := net.ParseIP("127.0.0.1")
	test.Assert(t, ip[0].To4().Equal(expected), "wrong ipv4 address")
	expected = net.ParseIP("::1")
	test.Assert(t, ip[1].To16().Equal(expected), "wrong ipv6 address")

	// IPv6 error, IPv4 success
	ip, err = obj.LookupHost(context.Background(), "v6error.letsencrypt.org")
	t.Logf("v6error.letsencrypt.org - IP: %s, Err: %s", ip, err)
	test.AssertNotError(t, err, "Not an error to exist")
	test.Assert(t, len(ip) == 1, "Should have 1 IP")
	expected = net.ParseIP("127.0.0.1")
	test.Assert(t, ip[0].To4().Equal(expected), "wrong ipv4 address")

	// IPv6 success, IPv4 error
	ip, err = obj.LookupHost(context.Background(), "v4error.letsencrypt.org")
	t.Logf("v4error.letsencrypt.org - IP: %s, Err: %s", ip, err)
	test.AssertNotError(t, err, "Not an error to exist")
	test.Assert(t, len(ip) == 1, "Should have 1 IP")
	expected = net.ParseIP("::1")
	test.Assert(t, ip[0].To16().Equal(expected), "wrong ipv6 address")

	// IPv6 error, IPv4 error
	// Should return the IPv4 error (Refused) and not IPv6 error (NotImplemented)
	hostname := "dualstackerror.letsencrypt.org"
	ip, err = obj.LookupHost(context.Background(), hostname)
	t.Logf("%s - IP: %s, Err: %s", hostname, ip, err)
	test.AssertError(t, err, "Should be an error")
	expectedErr := DNSError{dns.TypeA, hostname, nil, dns.RcodeRefused}
	if err, ok := err.(*DNSError); !ok || *err != expectedErr {
		t.Errorf("Looking up %s, got %#v, expected %#v", hostname, err, expectedErr)
	}
}

func TestDNSNXDOMAIN(t *testing.T) {
	obj := NewTestDNSClientImpl(time.Second*10, []string{dnsLoopbackAddr}, testStats, clock.NewFake(), 1)

	hostname := "nxdomain.letsencrypt.org"
	_, err := obj.LookupHost(context.Background(), hostname)
	expected := DNSError{dns.TypeA, hostname, nil, dns.RcodeNameError}
	if err, ok := err.(*DNSError); !ok || *err != expected {
		t.Errorf("Looking up %s, got %#v, expected %#v", hostname, err, expected)
	}

	_, _, err = obj.LookupTXT(context.Background(), hostname)
	expected.recordType = dns.TypeTXT
	if err, ok := err.(*DNSError); !ok || *err != expected {
		t.Errorf("Looking up %s, got %#v, expected %#v", hostname, err, expected)
	}
}

func TestDNSLookupCAA(t *testing.T) {
	obj := NewTestDNSClientImpl(time.Second*10, []string{dnsLoopbackAddr}, testStats, clock.NewFake(), 1)

	caas, _, err := obj.LookupCAA(context.Background(), "bracewel.net")
	test.AssertNotError(t, err, "CAA lookup failed")
	test.Assert(t, len(caas) > 0, "Should have CAA records")

	caas, _, err = obj.LookupCAA(context.Background(), "nonexistent.letsencrypt.org")
	test.AssertNotError(t, err, "CAA lookup failed")
	test.Assert(t, len(caas) == 0, "Shouldn't have CAA records")

	caas, _, err = obj.LookupCAA(context.Background(), "cname.example.com")
	test.AssertNotError(t, err, "CAA lookup failed")
	test.Assert(t, len(caas) > 0, "Should follow CNAME to find CAA")

	_, cnames, err := obj.LookupCAA(context.Background(), "dname.example.com")
	test.AssertNotError(t, err, "CAA lookup failed")
	test.Assert(t, len(cnames) > 0, "Should treat DNAME as CNAME")
}

func TestDNSTXTAuthorities(t *testing.T) {
	obj := NewTestDNSClientImpl(time.Second*10, []string{dnsLoopbackAddr}, testStats, clock.NewFake(), 1)

	_, auths, err := obj.LookupTXT(context.Background(), "letsencrypt.org")

	test.AssertNotError(t, err, "TXT lookup failed")
	test.AssertEquals(t, len(auths), 1)
	test.AssertEquals(t, auths[0], "letsencrypt.org.	0	IN	SOA	ns.letsencrypt.org. master.letsencrypt.org. 1 1 1 1 1")
}

func TestIsPrivateIP(t *testing.T) {
	test.Assert(t, isPrivateV4(net.ParseIP("127.0.0.1")), "should be private")
	test.Assert(t, isPrivateV4(net.ParseIP("192.168.254.254")), "should be private")
	test.Assert(t, isPrivateV4(net.ParseIP("10.255.0.3")), "should be private")
	test.Assert(t, isPrivateV4(net.ParseIP("172.16.255.255")), "should be private")
	test.Assert(t, isPrivateV4(net.ParseIP("172.31.255.255")), "should be private")
	test.Assert(t, !isPrivateV4(net.ParseIP("128.0.0.1")), "should be private")
	test.Assert(t, !isPrivateV4(net.ParseIP("192.169.255.255")), "should not be private")
	test.Assert(t, !isPrivateV4(net.ParseIP("9.255.0.255")), "should not be private")
	test.Assert(t, !isPrivateV4(net.ParseIP("172.32.255.255")), "should not be private")

	test.Assert(t, isPrivateV6(net.ParseIP("::0")), "should be private")
	test.Assert(t, isPrivateV6(net.ParseIP("::1")), "should be private")
	test.Assert(t, !isPrivateV6(net.ParseIP("::2")), "should not be private")

	test.Assert(t, isPrivateV6(net.ParseIP("fe80::1")), "should be private")
	test.Assert(t, isPrivateV6(net.ParseIP("febf::1")), "should be private")
	test.Assert(t, !isPrivateV6(net.ParseIP("fec0::1")), "should not be private")
	test.Assert(t, !isPrivateV6(net.ParseIP("feff::1")), "should not be private")

	test.Assert(t, isPrivateV6(net.ParseIP("ff00::1")), "should be private")
	test.Assert(t, isPrivateV6(net.ParseIP("ff10::1")), "should be private")
	test.Assert(t, isPrivateV6(net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")), "should be private")

	test.Assert(t, isPrivateV6(net.ParseIP("2002::")), "should be private")
	test.Assert(t, isPrivateV6(net.ParseIP("2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff")), "should be private")
	test.Assert(t, isPrivateV6(net.ParseIP("0100::")), "should be private")
	test.Assert(t, isPrivateV6(net.ParseIP("0100::0000:ffff:ffff:ffff:ffff")), "should be private")
	test.Assert(t, !isPrivateV6(net.ParseIP("0100::0001:0000:0000:0000:0000")), "should be private")
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
		maxTries          int
		te                *testExchanger
		expected          error
		expectedCount     int
		metricsAllRetries int
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
			expected:          netError,
			expectedCount:     3,
			metricsAllRetries: 1,
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
			expected:          netError,
			expectedCount:     3,
			metricsAllRetries: 1,
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
		dr := NewTestDNSClientImpl(time.Second*10, []string{dnsLoopbackAddr}, testStats, clock.NewFake(), tc.maxTries)
		dr.dnsClient = tc.te
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
		if tc.metricsAllRetries > 0 {
			test.AssertEquals(t, test.CountCounterVec(
				"qtype",
				"TXT",
				dr.usedAllRetriesCounter), tc.metricsAllRetries)
		}
	}

	dr := NewTestDNSClientImpl(time.Second*10, []string{dnsLoopbackAddr}, testStats, clock.NewFake(), 3)
	dr.dnsClient = &testExchanger{errs: []error{isTempErr, isTempErr, nil}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := dr.LookupTXT(ctx, "example.com")
	if err == nil ||
		err.Error() != "DNS problem: query timed out looking up TXT for example.com" {
		t.Errorf("expected %s, got %s", context.Canceled, err)
	}

	dr.dnsClient = &testExchanger{errs: []error{isTempErr, isTempErr, nil}}
	ctx, _ = context.WithTimeout(context.Background(), -10*time.Hour)
	_, _, err = dr.LookupTXT(ctx, "example.com")
	if err == nil ||
		err.Error() != "DNS problem: query timed out looking up TXT for example.com" {
		t.Errorf("expected %s, got %s", context.DeadlineExceeded, err)
	}

	dr.dnsClient = &testExchanger{errs: []error{isTempErr, isTempErr, nil}}
	ctx, deadlineCancel := context.WithTimeout(context.Background(), -10*time.Hour)
	deadlineCancel()
	_, _, err = dr.LookupTXT(ctx, "example.com")
	if err == nil ||
		err.Error() != "DNS problem: query timed out looking up TXT for example.com" {
		t.Errorf("expected %s, got %s", context.DeadlineExceeded, err)
	}

	test.AssertEquals(t, test.CountCounterVec(
		"qtype",
		"TXT",
		dr.cancelCounter), 3)
}

type tempError bool

func (t tempError) Temporary() bool { return bool(t) }
func (t tempError) Error() string   { return fmt.Sprintf("Temporary: %t", t) }

func TestReadHostList(t *testing.T) {
	res, err := ReadHostList("")
	if res != nil {
		t.Errorf("Expected res to be nil")
	}
	if err != nil {
		t.Errorf("Expected err to be nil: %s", err)
	}
	res, err = ReadHostList("../test/caa-servfail-exceptions.txt")
	if err != nil {
		t.Errorf("Expected err to be nil: %s", err)
	}
	if len(res) != 1 {
		t.Errorf("Wrong size of host list: %d", len(res))
	}
	if res["servfailexception.example.com"] != true {
		t.Errorf("Didn't find servfailexception.example.com in list")
	}
}
