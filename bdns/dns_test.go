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
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
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
					t.Fatalf("LookupA(%s) retuned %d addrs, but want %d", tc.hostname, len(res.Final), len(tc.wantIPs))
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
					t.Fatalf("LookupA(%s) retuned %d addrs, but want %d", tc.hostname, len(res.Final), len(tc.wantIPs))
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
	expected := Error{dns.TypeTXT, hostname, nil, dns.RcodeNameError, nil}
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

func (te *testExchanger) ExchangeContext(ctx context.Context, m *dns.Msg, a string) (*dns.Msg, time.Duration, error) {
	if ctx.Err() != nil {
		return nil, 0, ctx.Err()
	}

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
	isTimeoutErr := &url.Error{Op: "read", Err: testTimeoutError(true)}
	nonTimeoutErr := &url.Error{Op: "read", Err: testTimeoutError(false)}
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
		// Immediate non-OpError, error returns immediately
		{
			name:     "non-operror",
			maxTries: 3,
			te: &testExchanger{
				errs: []error{errors.New("nope")},
			},
			expected:      servFailError,
			expectedCount: 1,
		},
		// Timeout err, then non-OpError stops at two tries
		{
			name:     "err-then-non-operror",
			maxTries: 3,
			te: &testExchanger{
				errs: []error{isTimeoutErr, errors.New("nope")},
			},
			expected:      servFailError,
			expectedCount: 2,
		},
		// Timeout error given always
		{
			name:     "persistent-timeout-error",
			maxTries: 3,
			te: &testExchanger{
				errs: []error{
					isTimeoutErr,
					isTimeoutErr,
					isTimeoutErr,
				},
			},
			expected:          timeoutFailError,
			expectedCount:     3,
			metricsAllRetries: 1,
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
		// Timeout error given just once causes two tries
		{
			name:     "single-timeout-error",
			maxTries: 3,
			te: &testExchanger{
				errs: []error{
					isTimeoutErr,
					nil,
				},
			},
			expected:      nil,
			expectedCount: 2,
		},
		// Timeout error given twice causes three tries
		{
			name:     "double-timeout-error",
			maxTries: 3,
			te: &testExchanger{
				errs: []error{
					isTimeoutErr,
					isTimeoutErr,
					nil,
				},
			},
			expected:      nil,
			expectedCount: 3,
		},
		// Timeout error given thrice causes three tries and fails
		{
			name:     "triple-timeout-error",
			maxTries: 3,
			te: &testExchanger{
				errs: []error{
					isTimeoutErr,
					isTimeoutErr,
					isTimeoutErr,
				},
			},
			expected:          timeoutFailError,
			expectedCount:     3,
			metricsAllRetries: 1,
		},
		// timeout then non-timeout error causes two retries
		{
			name:     "timeout-nontimeout-error",
			maxTries: 3,
			te: &testExchanger{
				errs: []error{
					isTimeoutErr,
					nonTimeoutErr,
				},
			},
			expected:      servFailError,
			expectedCount: 2,
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
				test.AssertMetricWithLabelsEquals(
					t, dr.timeoutCounter, prometheus.Labels{
						"qtype":    "TXT",
						"result":   "out of retries",
						"resolver": "127.0.0.1",
						"isTLD":    "false",
					}, tc.metricsAllRetries)
			}
		})
	}
}

func TestRetryMetrics(t *testing.T) {
	staticProvider, err := NewStaticProvider([]string{dnsLoopbackAddr})
	test.AssertNotError(t, err, "Got error creating StaticProvider")

	// This lookup should not be retried, because the error comes from the
	// context itself being cancelled. It should never see the error in the
	// testExchanger, because the fake exchanger (like the real http package)
	// checks for cancellation before doing any work.
	testClient := New(time.Second*10, staticProvider, metrics.NoopRegisterer, clock.NewFake(), 3, "", blog.UseMock(), tlsConfig)
	dr := testClient.(*impl)
	dr.exchanger = &testExchanger{errs: []error{errors.New("oops")}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, _, err = dr.LookupTXT(ctx, "example.com")
	if err == nil ||
		err.Error() != "DNS problem: query timed out (and was canceled) looking up TXT for example.com" {
		t.Errorf("expected %s, got %s", context.Canceled, err)
	}
	test.AssertMetricWithLabelsEquals(
		t, dr.timeoutCounter, prometheus.Labels{
			"qtype":    "TXT",
			"result":   "canceled",
			"resolver": "127.0.0.1",
		}, 1)

	// Same as above, except rather than cancelling the context ourselves, we
	// let the go runtime cancel it as a result of a deadline in the past.
	testClient = New(time.Second*10, staticProvider, metrics.NoopRegisterer, clock.NewFake(), 3, "", blog.UseMock(), tlsConfig)
	dr = testClient.(*impl)
	dr.exchanger = &testExchanger{errs: []error{errors.New("oops")}}
	ctx, cancel = context.WithTimeout(t.Context(), -10*time.Hour)
	defer cancel()
	_, _, err = dr.LookupTXT(ctx, "example.com")
	if err == nil ||
		err.Error() != "DNS problem: query timed out looking up TXT for example.com" {
		t.Errorf("expected %s, got %s", context.DeadlineExceeded, err)
	}
	test.AssertMetricWithLabelsEquals(
		t, dr.timeoutCounter, prometheus.Labels{
			"qtype":    "TXT",
			"result":   "deadline exceeded",
			"resolver": "127.0.0.1",
		}, 1)
}

type testTimeoutError bool

func (t testTimeoutError) Timeout() bool { return bool(t) }
func (t testTimeoutError) Error() string { return fmt.Sprintf("Timeout: %t", t) }

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
// if present in `brokenAddresses`, returns a timeout error.
func (e *rotateFailureExchanger) ExchangeContext(_ context.Context, m *dns.Msg, a string) (*dns.Msg, time.Duration, error) {
	e.Lock()
	defer e.Unlock()

	// Track that exchange was called for the given server
	e.lookups[a]++

	// If its a broken server, return a retryable error
	if e.brokenAddresses[a] {
		isTimeoutErr := &url.Error{Op: "read", Err: testTimeoutError(true)}
		return nil, 2 * time.Millisecond, isTimeoutErr
	}

	return m, 2 * time.Millisecond, nil
}

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
	staticProvider, err := NewStaticProvider(dnsServers)
	test.AssertNotError(t, err, "Got error creating StaticProvider")

	maxTries := 5
	client := New(time.Second*10, staticProvider, metrics.NoopRegisterer, clock.NewFake(), maxTries, "", blog.UseMock(), tlsConfig)

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

	// Perform a bunch of lookups. We choose the initial server randomly. Any time
	// A or B is chosen there should be an error and a retry using the next server
	// in the list. Since we configured maxTries to be larger than the number of
	// servers *all* queries should eventually succeed by being retried against
	// server "[2606:4700:4700::1111]:53".
	for range maxTries * 2 {
		_, resolver, err := client.LookupTXT(context.Background(), "example.com")
		test.AssertEquals(t, resolver, "[2606:4700:4700::1111]:53")
		// Any errors are unexpected - server "[2606:4700:4700::1111]:53" should
		// have responded without error.
		test.AssertNotError(t, err, "Expected no error from eventual retry with functional server")
	}

	// We expect that the A and B servers had a non-zero number of lookups
	// attempted.
	test.Assert(t, mock.lookups["a:53"] > 0, "Expected A server to have non-zero lookup attempts")
	test.Assert(t, mock.lookups["b:53"] > 0, "Expected B server to have non-zero lookup attempts")

	// We expect that the server "[2606:4700:4700::1111]:53" eventually served
	// all of the lookups attempted.
	test.AssertEquals(t, mock.lookups["[2606:4700:4700::1111]:53"], maxTries*2)

}

type mockTimeoutURLError struct{}

func (m *mockTimeoutURLError) Error() string { return "whoops, oh gosh" }
func (m *mockTimeoutURLError) Timeout() bool { return true }

type dohAlwaysRetryExchanger struct {
	sync.Mutex
	err error
}

func (dohE *dohAlwaysRetryExchanger) ExchangeContext(_ context.Context, m *dns.Msg, a string) (*dns.Msg, time.Duration, error) {
	dohE.Lock()
	defer dohE.Unlock()

	timeoutURLerror := &url.Error{
		Op:  "GET",
		URL: "https://example.com",
		Err: &mockTimeoutURLError{},
	}

	return nil, time.Second, timeoutURLerror
}

func TestDOHMetric(t *testing.T) {
	staticProvider, err := NewStaticProvider([]string{dnsLoopbackAddr})
	test.AssertNotError(t, err, "Got error creating StaticProvider")

	testClient := New(time.Second*11, staticProvider, metrics.NoopRegisterer, clock.NewFake(), 0, "", blog.UseMock(), tlsConfig)
	resolver := testClient.(*impl)
	resolver.exchanger = &dohAlwaysRetryExchanger{err: &url.Error{Op: "read", Err: testTimeoutError(true)}}

	// Starting out, we should count 0 "out of retries" errors.
	test.AssertMetricWithLabelsEquals(t, resolver.timeoutCounter, prometheus.Labels{"qtype": "None", "type": "out of retries", "resolver": "127.0.0.1", "isTLD": "false"}, 0)

	// Trigger the error.
	_, _, _ = resolver.exchangeOne(context.Background(), "example.com", 0)

	// Now, we should count 1 "out of retries" errors.
	test.AssertMetricWithLabelsEquals(t, resolver.timeoutCounter, prometheus.Labels{"qtype": "None", "type": "out of retries", "resolver": "127.0.0.1", "isTLD": "false"}, 1)
}
