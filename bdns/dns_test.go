package bdns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
)

const dnsLoopbackAddr = "127.0.0.1:4053"

func mockDNSQuery(w http.ResponseWriter, httpReq *http.Request) {
	if httpReq.Header.Get("Content-Type") != "application/dns-message" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "client didn't send Content-Type: application/dns-message")
	}
	if httpReq.Header.Get("Accept") != "application/dns-message" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "client didn't accept Content-Type: application/dns-message")
	}

	requestBody, err := io.ReadAll(httpReq.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "reading body: %s", err)
	}
	httpReq.Body.Close()

	r := new(dns.Msg)
	err = r.Unpack(requestBody)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "unpacking request: %s", err)
	}

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
				record.AAAA = net.ParseIP("2602:80a:6000:abad:cafe::1")
				appendAnswer(record)
			}
			if q.Name == "dualstack.letsencrypt.org." {
				record := new(dns.AAAA)
				record.Hdr = dns.RR_Header{Name: "dualstack.letsencrypt.org.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0}
				record.AAAA = net.ParseIP("2602:80a:6000:abad:cafe::1")
				appendAnswer(record)
			}
			if q.Name == "v4error.letsencrypt.org." {
				record := new(dns.AAAA)
				record.Hdr = dns.RR_Header{Name: "v4error.letsencrypt.org.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0}
				record.AAAA = net.ParseIP("2602:80a:6000:abad:cafe::1")
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
				record.A = net.ParseIP("64.112.117.1")
				appendAnswer(record)
			}
			if q.Name == "dualstack.letsencrypt.org." {
				record := new(dns.A)
				record.Hdr = dns.RR_Header{Name: "dualstack.letsencrypt.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
				record.A = net.ParseIP("64.112.117.1")
				appendAnswer(record)
			}
			if q.Name == "v6error.letsencrypt.org." {
				record := new(dns.A)
				record.Hdr = dns.RR_Header{Name: "dualstack.letsencrypt.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
				record.A = net.ParseIP("64.112.117.1")
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
			if q.Name == "gonetld." {
				m.SetRcode(r, dns.RcodeNameError)
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

	body, err := m.Pack()
	if err != nil {
		fmt.Fprintf(os.Stderr, "packing reply: %s\n", err)
	}
	w.Header().Set("Content-Type", "application/dns-message")
	_, err = w.Write(body)
	if err != nil {
		panic(err) // running tests, so panic is OK
	}
}

func serveLoopResolver(stopChan chan bool) {
	m := http.NewServeMux()
	m.HandleFunc("/dns-query", mockDNSQuery)
	httpServer := &http.Server{
		Addr:         dnsLoopbackAddr,
		Handler:      m,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	}
	go func() {
		cert := "../test/certs/ipki/localhost/cert.pem"
		key := "../test/certs/ipki/localhost/key.pem"
		err := httpServer.ListenAndServeTLS(cert, key)
		if err != nil {
			fmt.Println(err)
		}
	}()
	go func() {
		<-stopChan
		err := httpServer.Shutdown(context.Background())
		if err != nil {
			log.Fatal(err)
		}
	}()
}

func pollServer() {
	backoff := 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(backoff)

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "Timeout reached while testing for the dns server to come up")
			os.Exit(1)
		case <-ticker.C:
			conn, _ := dns.DialTimeout("udp", dnsLoopbackAddr, backoff)
			if conn != nil {
				_ = conn.Close()
				return
			}
		}
	}
}

// tlsConfig is used for the TLS config of client instances that talk to the
// DoH server set up in TestMain.
var tlsConfig *tls.Config

func TestMain(m *testing.M) {
	root, err := os.ReadFile("../test/certs/ipki/minica.pem")
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(root)
	tlsConfig = &tls.Config{
		RootCAs: pool,
	}

	stop := make(chan bool, 1)
	serveLoopResolver(stop)
	pollServer()
	ret := m.Run()
	stop <- true
	os.Exit(ret)
}

func TestDNSNoServers(t *testing.T) {
	staticProvider, err := NewStaticProvider([]string{})
	test.AssertNotError(t, err, "Got error creating StaticProvider")

	obj := New(time.Hour, staticProvider, metrics.NoopRegisterer, clock.NewFake(), 1, "", blog.UseMock(), tlsConfig)

	_, resolver, err := obj.LookupA(context.Background(), "letsencrypt.org")
	test.AssertEquals(t, resolver, "")
	test.AssertError(t, err, "No servers")

	_, resolver, err = obj.LookupAAAA(context.Background(), "letsencrypt.org")
	test.AssertEquals(t, resolver, "")
	test.AssertError(t, err, "No servers")

	_, resolver, err = obj.LookupTXT(context.Background(), "letsencrypt.org")
	test.AssertEquals(t, resolver, "")
	test.AssertError(t, err, "No servers")

	_, resolver, err = obj.LookupCAA(context.Background(), "letsencrypt.org")
	test.AssertEquals(t, resolver, "")
	test.AssertError(t, err, "No servers")
}

func TestDNSOneServer(t *testing.T) {
	staticProvider, err := NewStaticProvider([]string{dnsLoopbackAddr})
	test.AssertNotError(t, err, "Got error creating StaticProvider")

	obj := New(time.Second*10, staticProvider, metrics.NoopRegisterer, clock.NewFake(), 1, "", blog.UseMock(), tlsConfig)

	_, resolver, err := obj.LookupA(context.Background(), "letsencrypt.org")
	test.AssertNotError(t, err, "No message")
	test.AssertEquals(t, resolver, "127.0.0.1:4053")
}

func TestDNSDuplicateServers(t *testing.T) {
	staticProvider, err := NewStaticProvider([]string{dnsLoopbackAddr, dnsLoopbackAddr})
	test.AssertNotError(t, err, "Got error creating StaticProvider")

	obj := New(time.Second*10, staticProvider, metrics.NoopRegisterer, clock.NewFake(), 1, "", blog.UseMock(), tlsConfig)

	_, resolver, err := obj.LookupA(context.Background(), "letsencrypt.org")
	test.AssertNotError(t, err, "No message")
	test.AssertEquals(t, resolver, "127.0.0.1:4053")
}

func TestDNSServFail(t *testing.T) {
	staticProvider, err := NewStaticProvider([]string{dnsLoopbackAddr})
	test.AssertNotError(t, err, "Got error creating StaticProvider")

	obj := New(time.Second*10, staticProvider, metrics.NoopRegisterer, clock.NewFake(), 1, "", blog.UseMock(), tlsConfig)
	bad := "servfail.com"

	_, _, err = obj.LookupTXT(context.Background(), "servfail.com")
	test.AssertError(t, err, "LookupTXT didn't return an error")

	_, _, err = obj.LookupA(context.Background(), bad)
	test.AssertError(t, err, "LookupA didn't return an error")

	_, _, err = obj.LookupAAAA(context.Background(), bad)
	test.AssertError(t, err, "LookupAAAA didn't return an error")

	_, _, err = obj.LookupCAA(context.Background(), bad)
	test.AssertError(t, err, "LookupCAA didn't return an error")
}

func TestDNSLookupTXT(t *testing.T) {
	staticProvider, err := NewStaticProvider([]string{dnsLoopbackAddr})
	test.AssertNotError(t, err, "Got error creating StaticProvider")

	obj := New(time.Second*10, staticProvider, metrics.NoopRegisterer, clock.NewFake(), 1, "", blog.UseMock(), tlsConfig)

	_, _, err = obj.LookupTXT(context.Background(), "letsencrypt.org")
	test.AssertNotError(t, err, "No message")

	txt, _, err := obj.LookupTXT(context.Background(), "split-txt.letsencrypt.org")
	test.AssertNotError(t, err, "No message")
	test.AssertEquals(t, len(txt.Final), 1)
	test.AssertEquals(t, strings.Join(txt.Final[0].Txt, ""), "abc")
}

func TestDNSLookupA(t *testing.T) {
	staticProvider, err := NewStaticProvider([]string{dnsLoopbackAddr})
	test.AssertNotError(t, err, "Got error creating StaticProvider")

	obj := New(time.Second*10, staticProvider, metrics.NoopRegisterer, clock.NewFake(), 1, "", blog.UseMock(), tlsConfig)

	for _, tc := range []struct {
		name      string
		hostname  string
		wantIPs   []net.IP
		wantError string
	}{
		{
			name:      "SERVFAIL",
			hostname:  "servfail.com",
			wantError: "SERVFAIL looking up A for servfail.com",
		},
		{
			name:     "No Records",
			hostname: "nonexistent.letsencrypt.org",
			wantIPs:  nil,
		},
		{
			name:     "Single IPv4",
			hostname: "cps.letsencrypt.org",
			wantIPs:  []net.IP{net.ParseIP("64.112.117.1")},
		},
		{
			name:     "Single IPv6",
			hostname: "v6.letsencrypt.org",
			wantIPs:  nil,
		},
		{
			name:     "Both IPv6 and IPv4",
			hostname: "dualstack.letsencrypt.org",
			wantIPs:  []net.IP{net.ParseIP("64.112.117.1")},
		},
		{
			name:     "IPv6 error and IPv4 success",
			hostname: "v6error.letsencrypt.org",
			wantIPs:  []net.IP{net.ParseIP("64.112.117.1")},
		},
		{
			name:      "IPv6 success and IPv4 error",
			hostname:  "v4error.letsencrypt.org",
			wantError: "NOTIMP looking up A for v4error.letsencrypt.org",
		},
		{
			name:      "Both IPv6 and IPv4 error",
			hostname:  "dualstackerror.letsencrypt.org",
			wantError: "REFUSED looking up A for dualstackerror.letsencrypt.org",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, resolver, err := obj.LookupA(context.Background(), tc.hostname)

			wantResolver := "127.0.0.1:4053"
			if resolver != wantResolver {
				t.Errorf("LookupA(%s) used resolver %q, but want %q", tc.hostname, resolver, wantResolver)
			}

			if tc.wantError != "" {
				if err == nil {
					t.Fatalf("LookupA(%s) = success, but want error %q", tc.hostname, tc.wantError)
				}
				if !strings.Contains(err.Error(), tc.wantError) {
					t.Errorf("LookupA(%s) = %q, but want error %q", tc.hostname, err, tc.wantError)
				}
			} else {
				if err != nil {
					t.Fatalf("LookupA(%s) = %q, but want success", tc.hostname, err)
				}
				if len(res.Final) != len(tc.wantIPs) {
					t.Fatalf("LookupA(%s) returned %d addrs, but want %d", tc.hostname, len(res.Final), len(tc.wantIPs))
				}
				for i := range len(tc.wantIPs) {
					if !res.Final[i].A.Equal(tc.wantIPs[i]) {
						t.Errorf("LookupA(%s) = %s, but want %s", tc.hostname, res.Final[i].A, tc.wantIPs[i])
					}
				}
			}
		})
	}
}

func TestDNSLookupAAAA(t *testing.T) {
	staticProvider, err := NewStaticProvider([]string{dnsLoopbackAddr})
	test.AssertNotError(t, err, "Got error creating StaticProvider")

	obj := New(time.Second*10, staticProvider, metrics.NoopRegisterer, clock.NewFake(), 1, "", blog.UseMock(), tlsConfig)

	for _, tc := range []struct {
		name      string
		hostname  string
		wantIPs   []net.IP
		wantError string
	}{
		{
			name:      "SERVFAIL",
			hostname:  "servfail.com",
			wantError: "SERVFAIL looking up AAAA for servfail.com",
		},
		{
			name:     "No Records",
			hostname: "nonexistent.letsencrypt.org",
			wantIPs:  nil,
		},
		{
			name:     "Single IPv4",
			hostname: "cps.letsencrypt.org",
			wantIPs:  nil,
		},
		{
			name:     "Single IPv6",
			hostname: "v6.letsencrypt.org",
			wantIPs:  []net.IP{net.ParseIP("2602:80a:6000:abad:cafe::1")},
		},
		{
			name:     "Both IPv6 and IPv4",
			hostname: "dualstack.letsencrypt.org",
			wantIPs:  []net.IP{net.ParseIP("2602:80a:6000:abad:cafe::1")},
		},
		{
			name:      "IPv6 error and IPv4 success",
			hostname:  "v6error.letsencrypt.org",
			wantError: "NOTIMP looking up AAAA for v6error.letsencrypt.org",
		},
		{
			name:     "IPv6 success and IPv4 error",
			hostname: "v4error.letsencrypt.org",
			wantIPs:  []net.IP{net.ParseIP("2602:80a:6000:abad:cafe::1")},
		},
		{
			name:      "Both IPv6 and IPv4 error",
			hostname:  "dualstackerror.letsencrypt.org",
			wantError: "NOTIMP looking up AAAA for dualstackerror.letsencrypt.org",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, resolver, err := obj.LookupAAAA(context.Background(), tc.hostname)

			wantResolver := "127.0.0.1:4053"
			if resolver != wantResolver {
				t.Errorf("LookupA(%s) used resolver %q, but want %q", tc.hostname, resolver, wantResolver)
			}

			if tc.wantError != "" {
				if err == nil {
					t.Fatalf("LookupA(%s) = success, but want error %q", tc.hostname, tc.wantError)
				}
				if !strings.Contains(err.Error(), tc.wantError) {
					t.Errorf("LookupA(%s) = %q, but want error %q", tc.hostname, err, tc.wantError)
				}
			} else {
				if err != nil {
					t.Fatalf("LookupA(%s) = %q, but want success", tc.hostname, err)
				}
				if len(res.Final) != len(tc.wantIPs) {
					t.Fatalf("LookupA(%s) returned %d addrs, but want %d", tc.hostname, len(res.Final), len(tc.wantIPs))
				}
				for i := range len(tc.wantIPs) {
					if !res.Final[i].AAAA.Equal(tc.wantIPs[i]) {
						t.Errorf("LookupA(%s) = %s, but want %s", tc.hostname, res.Final[i].AAAA, tc.wantIPs[i])
					}
				}
			}
		})
	}
}

func TestDNSNXDOMAIN(t *testing.T) {
	staticProvider, err := NewStaticProvider([]string{dnsLoopbackAddr})
	test.AssertNotError(t, err, "Got error creating StaticProvider")

	obj := New(time.Second*10, staticProvider, metrics.NoopRegisterer, clock.NewFake(), 1, "", blog.UseMock(), tlsConfig)
	hostname := "nxdomain.letsencrypt.org"

	_, _, err = obj.LookupA(context.Background(), hostname)
	test.AssertContains(t, err.Error(), "NXDOMAIN looking up A for")

	_, _, err = obj.LookupAAAA(context.Background(), hostname)
	test.AssertContains(t, err.Error(), "NXDOMAIN looking up AAAA for")

	_, _, err = obj.LookupTXT(context.Background(), hostname)
	expected := Error{dns.TypeTXT, hostname, nil, dns.RcodeNameError, nil, false}
	test.AssertDeepEquals(t, err, expected)
}

func TestDNSLookupCAA(t *testing.T) {
	staticProvider, err := NewStaticProvider([]string{dnsLoopbackAddr})
	test.AssertNotError(t, err, "Got error creating StaticProvider")

	obj := New(time.Second*10, staticProvider, metrics.NoopRegisterer, clock.NewFake(), 1, "", blog.UseMock(), tlsConfig)
	removeIDExp := regexp.MustCompile(" id: [[:digit:]]+")

	caas, resolver, err := obj.LookupCAA(context.Background(), "bracewel.net")
	test.AssertNotError(t, err, "CAA lookup failed")
	test.Assert(t, len(caas.Final) > 0, "Should have CAA records")
	test.AssertEquals(t, resolver, "127.0.0.1:4053")
	expectedResp := `;; opcode: QUERY, status: NOERROR, id: XXXX
;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;bracewel.net.	IN	 CAA

;; ANSWER SECTION:
bracewel.net.	0	IN	CAA	1 issue "letsencrypt.org"
`
	test.AssertEquals(t, removeIDExp.ReplaceAllString(caas.String(), " id: XXXX"), expectedResp)

	caas, resolver, err = obj.LookupCAA(context.Background(), "nonexistent.letsencrypt.org")
	test.AssertNotError(t, err, "CAA lookup failed")
	test.Assert(t, len(caas.Final) == 0, "Shouldn't have CAA records")
	test.AssertEquals(t, resolver, "127.0.0.1:4053")

	caas, resolver, err = obj.LookupCAA(context.Background(), "nxdomain.letsencrypt.org")
	test.AssertNotError(t, err, "CAA lookup failed")
	test.Assert(t, len(caas.Final) == 0, "Shouldn't have CAA records")
	test.AssertEquals(t, resolver, "127.0.0.1:4053")

	caas, resolver, err = obj.LookupCAA(context.Background(), "cname.example.com")
	test.AssertNotError(t, err, "CAA lookup failed")
	test.Assert(t, len(caas.Final) > 0, "Should follow CNAME to find CAA")
	test.AssertEquals(t, resolver, "127.0.0.1:4053")
	expectedResp = `;; opcode: QUERY, status: NOERROR, id: XXXX
;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;cname.example.com.	IN	 CAA

;; ANSWER SECTION:
caa.example.com.	0	IN	CAA	1 issue "letsencrypt.org"
`
	test.AssertEquals(t, removeIDExp.ReplaceAllString(caas.String(), " id: XXXX"), expectedResp)

	_, resolver, err = obj.LookupCAA(context.Background(), "gonetld")
	test.AssertError(t, err, "should fail for TLD NXDOMAIN")
	test.AssertContains(t, err.Error(), "NXDOMAIN")
	test.AssertEquals(t, resolver, "127.0.0.1:4053")
}

type testExchanger struct {
	sync.Mutex
	count int
	errs  []error
}

var errTooManyRequests = errors.New("too many requests")

func (te *testExchanger) ExchangeContext(_ context.Context, m *dns.Msg, a string) (*dns.Msg, time.Duration, error) {
	te.Lock()
	defer te.Unlock()
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
	}
	// Count every call, including ones past the end of errs, so that tests
	// notice extra requests.
	te.count++
	if te.count > len(te.errs) {
		return nil, 0, errTooManyRequests
	}
	err := te.errs[te.count-1]

	return msg, 2 * time.Millisecond, err
}

func TestRetry(t *testing.T) {
	// transportErr represents any internal error communicating with Unbound, e.g. TLS handshake or dial failure.
	transportErr := errors.New("transport error")
	servFailError := errors.New("DNS problem: server failure at resolver looking up TXT for example.com")
	timeoutFailError := errors.New("DNS problem: query timed out looking up TXT for example.com")
	type testCase struct {
		name              string
		maxTries          int
		te                *testExchanger
		expected          error
		expectedCount     int
		metricsAllRetries float64
	}
	tests := []*testCase{
		// The success on first try case
		{
			name:     "success",
			maxTries: 3,
			te: &testExchanger{
				errs: []error{nil},
			},
			expected:      nil,
			expectedCount: 1,
		},
		// Even with maxTries at 0, we should still let a single request go
		// through
		{
			name:     "zero-maxtries",
			maxTries: 0,
			te: &testExchanger{
				errs: []error{nil},
			},
			expected:      nil,
			expectedCount: 1,
		},
		{
			name:     "transport-error-then-success",
			maxTries: 3,
			te: &testExchanger{
				errs: []error{transportErr, nil},
			},
			expected:      nil,
			expectedCount: 2,
		},
		{
			name:     "two-transport-errors-then-success",
			maxTries: 3,
			te: &testExchanger{
				errs: []error{transportErr, transportErr, nil},
			},
			expected:      nil,
			expectedCount: 3,
		},
		{
			name:     "persistent-transport-error",
			maxTries: 3,
			te: &testExchanger{
				errs: []error{transportErr, transportErr, transportErr},
			},
			expected:          servFailError,
			expectedCount:     3,
			metricsAllRetries: 1,
		},
		{
			name:     "response-timeout-then-success",
			maxTries: 3,
			te: &testExchanger{
				errs: []error{errDohQueryTimeout, nil},
			},
			expected:      nil,
			expectedCount: 2,
		},
		{
			name:     "persistent-response-timeout",
			maxTries: 3,
			te: &testExchanger{
				errs: []error{errDohQueryTimeout, errDohQueryTimeout, errDohQueryTimeout},
			},
			expected:          timeoutFailError,
			expectedCount:     3,
			metricsAllRetries: 1,
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			staticProvider, err := NewStaticProvider([]string{dnsLoopbackAddr})
			test.AssertNotError(t, err, "Got error creating StaticProvider")

			testClient := New(time.Second*10, staticProvider, metrics.NoopRegisterer, clock.NewFake(), tc.maxTries, "", blog.UseMock(), tlsConfig)
			dr := testClient.(*impl)
			dr.exchanger = tc.te
			_, _, err = dr.LookupTXT(context.Background(), "example.com")
			if tc.te.count > len(tc.te.errs) {
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
				test.AssertMetricWithLabelsEquals(
					t, dr.timeoutCounter, prometheus.Labels{
						"qtype":    "TXT",
						"result":   "out of retries",
						"resolver": "127.0.0.1:4053",
						"isTLD":    "false",
					}, tc.metricsAllRetries)
			}
		})
	}
}

func TestRetryMetrics(t *testing.T) {
	staticProvider, err := NewStaticProvider([]string{dnsLoopbackAddr})
	test.AssertNotError(t, err, "Got error creating StaticProvider")

	// This lookup should not be retried, because the context is canceled before we start.
	testClient := New(time.Second*10, staticProvider, metrics.NoopRegisterer, clock.NewFake(), 3, "", blog.UseMock(), tlsConfig)
	dr := testClient.(*impl)
	te := &testExchanger{errs: []error{errDohQueryCanceled}}
	dr.exchanger = te
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, _, err = dr.LookupTXT(ctx, "example.com")
	if err == nil ||
		err.Error() != "DNS problem: query timed out (and was canceled) looking up TXT for example.com" {
		t.Errorf("expected %s, got %s", context.Canceled, err)
	}
	if te.count != 1 {
		t.Errorf("got %d tries, want 1", te.count)
	}
	test.AssertMetricWithLabelsEquals(
		t, dr.timeoutCounter, prometheus.Labels{
			"qtype":    "TXT",
			"result":   "canceled",
			"resolver": "127.0.0.1:4053",
		}, 1)
}

// rotateFailureExchanger is a dns.Exchange implementation that tracks a count
// of the number of calls to `Exchange` for a given address in the `lookups`
// map. For all addresses in the `brokenAddresses` map, a retryable error is
// returned from `Exchange`. This mock is used by `TestRotateServerOnErr`.
type rotateFailureExchanger struct {
	sync.Mutex
	lookups         map[string]int
	brokenAddresses map[string]bool
}

// ExchangeContext for rotateFailureExchanger tracks the `a` argument in `lookups` and
// if present in `brokenAddresses`, returns an error.
func (e *rotateFailureExchanger) ExchangeContext(_ context.Context, m *dns.Msg, a string) (*dns.Msg, time.Duration, error) {
	e.Lock()
	defer e.Unlock()

	// Track that exchange was called for the given server
	e.lookups[a]++

	// If its a broken server, return an error
	if e.brokenAddresses[a] {
		return nil, 2 * time.Millisecond, errors.New("broken server")
	}

	return m, 2 * time.Millisecond, nil
}

// fixedOrderProvider returns its servers in the same order every time.
type fixedOrderProvider struct {
	servers []string
}

func (p *fixedOrderProvider) Addrs() ([]string, error) {
	return p.servers, nil
}

func (p *fixedOrderProvider) Stop() {}

// TestRotateServerOnErr ensures that a retryable error returned from a DNS
// server will result in the retry being performed against the next server in
// the list.
func TestRotateServerOnErr(t *testing.T) {
	// Configure three DNS servers
	dnsServers := []string{
		"a:53", "b:53", "[2606:4700:4700::1111]:53",
	}

	// Set up a DNS client using these servers that will retry queries up to
	// a maximum of 5 times. It's important to choose a maxTries value >= the
	// number of dnsServers to ensure we always get around to trying the one
	// working server
	maxTries := 5
	client := New(time.Second*10, &fixedOrderProvider{servers: dnsServers}, metrics.NoopRegisterer, clock.NewFake(), maxTries, "", blog.UseMock(), tlsConfig)

	// Configure a mock exchanger that will always return a retryable error for
	// servers A and B. This will force server "[2606:4700:4700::1111]:53" to do
	// all the work once retries reach it.
	mock := &rotateFailureExchanger{
		brokenAddresses: map[string]bool{
			"a:53": true,
			"b:53": true,
		},
		lookups: make(map[string]int),
	}
	client.(*impl).exchanger = mock

	// Perform a bunch of lookups. Any time A or B is chosen there should be an
	// error and a retry using the next server in the list. Since we configured
	// maxTries to be larger than the number of servers *all* queries should
	// eventually succeed by being retried against server "[2606:4700:4700::1111]:53".
	for range maxTries * 2 {
		_, resolver, err := client.LookupTXT(context.Background(), "example.com")
		test.AssertEquals(t, resolver, "[2606:4700:4700::1111]:53")
		// Any errors are unexpected - server "[2606:4700:4700::1111]:53" should
		// have responded without error.
		test.AssertNotError(t, err, "Expected no error from eventual retry with functional server")
	}

	// We expect that the A and B servers had one lookup attempted per query.
	test.AssertEquals(t, mock.lookups["a:53"], maxTries*2)
	test.AssertEquals(t, mock.lookups["b:53"], maxTries*2)

	// We expect that the server "[2606:4700:4700::1111]:53" eventually served
	// all of the lookups attempted.
	test.AssertEquals(t, mock.lookups["[2606:4700:4700::1111]:53"], maxTries*2)

}

// truncatedExchanger returns a truncated (TC bit set) response with the given
// Rcode. If a caller failed to check for truncation on a CAA query, it would
// otherwise be fooled into trusting an incomplete set of records, potentially
// missing an issue record that would forbid issuance.
type truncatedExchanger struct {
	rcode int
}

func (te truncatedExchanger) ExchangeContext(_ context.Context, m *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
	resp := new(dns.Msg)
	resp.SetReply(m)
	resp.Rcode = te.rcode
	resp.Truncated = true
	return resp, time.Millisecond, nil
}

func TestDNSCAATruncatedResponse(t *testing.T) {
	staticProvider, err := NewStaticProvider([]string{dnsLoopbackAddr})
	test.AssertNotError(t, err, "Got error creating StaticProvider")

	client := New(time.Second*10, staticProvider, metrics.NoopRegisterer, clock.NewFake(), 1, "", blog.NewMock(), tlsConfig)
	client.(*impl).exchanger = truncatedExchanger{rcode: dns.RcodeSuccess}

	_, _, err = client.LookupCAA(context.Background(), "example.com")
	test.AssertError(t, err, "expected error for truncated CAA response")
	test.AssertContains(t, err.Error(), "response was truncated")

	// A truncated NXDOMAIN response must not be treated as the usual
	// NXDOMAIN-as-empty-CAA-set special case for non-TLD names: we can't
	// trust an incomplete response to accurately reflect an NXDOMAIN.
	client.(*impl).exchanger = truncatedExchanger{rcode: dns.RcodeNameError}
	_, _, err = client.LookupCAA(context.Background(), "nonexistent.letsencrypt.org")
	test.AssertError(t, err, "expected error for truncated CAA response, even when NXDOMAIN-shaped")
	test.AssertContains(t, err.Error(), "response was truncated")
}

// newDoHExchanger calls New and extracts the exchanger and transport as pointers
// so tests can tweak timeout parameters (and therefore run faster).
func newDoHExchanger(t *testing.T) (*dohExchanger, *http.Transport) {
	t.Helper()
	staticProvider, err := NewStaticProvider([]string{dnsLoopbackAddr})
	test.AssertNotError(t, err, "Got error creating StaticProvider")
	client := New(time.Second, staticProvider, metrics.NoopRegisterer, clock.NewFake(), 1, "", blog.UseMock(), tlsConfig).(*impl)
	exchanger, ok := client.exchanger.(*dohExchanger)
	if !ok {
		t.Fatalf("exchanger is %T, want *dohExchanger", client.exchanger)
	}
	transport, ok := exchanger.hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", exchanger.hc.Transport)
	}
	return exchanger, transport
}

// TestDialTimeoutError makes every dial exceed net.Dialer.Timeout and
// confirms that this results in a DeadlineExceeded error. This is really testing
// Go's behavior, but it's useful for us to confirm Go's behavior since it
// justifies a string-matching hack in how we detect HTTP response timeouts.
func TestDialTimeoutError(t *testing.T) {
	// We set up a real listener so the kernel doesn't reply with "connection refused".
	// But we don't expect any requests to actually reach this.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %s", err)
	}
	defer ln.Close()

	exchanger, transport := newDoHExchanger(t)
	transport.DialContext = (&net.Dialer{
		Timeout: 10 * time.Millisecond,
		// "If Control is not nil, it is called after creating the network connection but before actually dialing."
		// This lets us simulate a dial timeout.
		Control: func(string, string, syscall.RawConn) error {
			time.Sleep(50 * time.Millisecond)
			return nil
		},
	}).DialContext

	req, err := http.NewRequestWithContext(t.Context(), "POST", "https://"+ln.Addr().String()+"/dns-query", nil)
	if err != nil {
		t.Fatalf("creating request: %s", err)
	}
	_, err = exchanger.hc.Do(req)
	if err == nil {
		t.Errorf("got no error, want error")
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("errors.Is(%s, context.DeadlineExceeded) = false, want true", err)
	}
}

// TestDoHExchangerTimeouts starts a real HTTP/2 server and tests timeouts
// and cancellations against it. This tests the error-matching behavior
// with an actual http.Client doing real work.
func TestDoHExchangerTimeouts(t *testing.T) {
	// exchange starts a server that accepts requests but never answers them,
	// sets up an exchanger and transport, sets the ResponseHeaderTimeout on
	// transport, and sends a query. If cancel is non-nil, it is called once the
	// server has received the request.
	//
	// Each call gets its own server, so a request that never reaches the
	// server (e.g. because ctx expired during the dial) can't be mistaken for
	// a later call's request.
	exchange := func(t *testing.T, ctx context.Context, responseHeaderTimeout time.Duration, cancel context.CancelFunc) error {
		t.Helper()
		// The `received` channel tells the test that the server got a request.
		received := make(chan *http.Request, 1)
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			received <- r
			select {
			case <-r.Context().Done():
			case <-t.Context().Done(): // unblock waiting requests when the test returns.
			}
		}))
		srv.EnableHTTP2 = true
		srv.StartTLS()
		t.Cleanup(srv.Close)

		exchanger, transport := newDoHExchanger(t)
		transport.TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		transport.ResponseHeaderTimeout = responseHeaderTimeout
		defer transport.CloseIdleConnections()

		go func() {
			select {
			case receivedReq := <-received:
				if receivedReq.ProtoMajor != 2 {
					t.Errorf("server got an HTTP/%d request, want HTTP/2", receivedReq.ProtoMajor)
				}
				if cancel != nil {
					cancel()
				}
			case <-t.Context().Done():
			}
		}()

		query := new(dns.Msg)
		query.SetQuestion("example.com.", dns.TypeA)

		_, _, err := exchanger.ExchangeContext(ctx, query, srv.Listener.Addr().String())
		return err
	}

	t.Run("response header timeout", func(t *testing.T) {
		err := exchange(t, t.Context(), 50*time.Millisecond, nil)
		if !errors.Is(err, errDohQueryTimeout) {
			t.Errorf("got %v, want dohQueryTimeout", err)
		}
	})

	t.Run("context deadline exceeded", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		err := exchange(t, ctx, time.Minute, nil)
		if !errors.Is(err, errDohQueryTimeout) {
			t.Errorf("got %v, want dohQueryTimeout", err)
		}
	})

	t.Run("context canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		err := exchange(t, ctx, time.Minute, cancel)
		if !errors.Is(err, errDohQueryCanceled) {
			t.Errorf("got %v, want dohQueryCanceled", err)
		}
	})
}
