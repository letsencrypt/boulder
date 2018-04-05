package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/miekg/dns"
)

type testSrv struct {
	mu         *sync.RWMutex
	txtRecords map[string][]string
}

type setRequest struct {
	Host  string `json:"host"`
	Value string `json:"value"`
}

func (ts *testSrv) setTXT(w http.ResponseWriter, r *http.Request) {
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var sr setRequest
	err = json.Unmarshal(msg, &sr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if sr.Host == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	host := strings.ToLower(sr.Host)
	ts.txtRecords[host] = append(ts.txtRecords[host], sr.Value)
	fmt.Printf("dns-srv: added TXT record for %s containing \"%s\"\n", sr.Host, sr.Value)
	w.WriteHeader(http.StatusOK)
}

func (ts *testSrv) clearTXT(w http.ResponseWriter, r *http.Request) {
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var sr setRequest
	err = json.Unmarshal(msg, &sr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if sr.Host == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	host := strings.ToLower(sr.Host)
	delete(ts.txtRecords, host)
	fmt.Printf("dns-srv: added TXT record for %s containing \"%s\"\n", sr.Host, sr.Value)
	w.WriteHeader(http.StatusOK)
}

func (ts *testSrv) dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	// Normally this test DNS server will return 127.0.0.1 for everything.
	// However, in some situations (for instance Docker), it's useful to return a
	// different hardcoded host. You can do so by setting the FAKE_DNS environment
	// variable.
	fakeDNS := os.Getenv("FAKE_DNS")
	if fakeDNS == "" {
		fakeDNS = "127.0.0.1"
	}
	for _, q := range r.Question {
		fmt.Printf("dns-srv: Query -- [%s] %s\n", q.Name, dns.TypeToString[q.Qtype])
		switch q.Qtype {
		case dns.TypeA:
			record := new(dns.A)
			record.Hdr = dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    0,
			}
			record.A = net.ParseIP(fakeDNS)

			m.Answer = append(m.Answer, record)
		case dns.TypeMX:
			record := new(dns.MX)
			record.Hdr = dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    0,
			}
			record.Mx = "mail." + q.Name
			record.Preference = 10

			m.Answer = append(m.Answer, record)
		case dns.TypeTXT:
			ts.mu.RLock()
			values, present := ts.txtRecords[q.Name]
			ts.mu.RUnlock()
			if !present {
				continue
			}
			fmt.Printf("dns-srv: Returning %d TXT records: %#v\n", len(values), values)
			for _, name := range values {
				record := new(dns.TXT)
				record.Hdr = dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    0,
				}
				record.Txt = []string{name}
				m.Answer = append(m.Answer, record)
			}
		case dns.TypeCAA:
			if q.Name == "bad-caa-reserved.com." || q.Name == "good-caa-reserved.com." {
				record := new(dns.CAA)
				record.Hdr = dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeCAA,
					Class:  dns.ClassINET,
					Ttl:    0,
				}
				record.Tag = "issue"
				if q.Name == "bad-caa-reserved.com." {
					record.Value = "sad-hacker-ca.invalid"
				} else if q.Name == "good-caa-reserved.com." {
					record.Value = "happy-hacker-ca.invalid"
				}
				m.Answer = append(m.Answer, record)
			}
		}
	}

	auth := new(dns.SOA)
	auth.Hdr = dns.RR_Header{Name: "boulder.invalid.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 0}
	auth.Ns = "ns.boulder.invalid."
	auth.Mbox = "master.boulder.invalid."
	auth.Serial = 1
	auth.Refresh = 1
	auth.Retry = 1
	auth.Expire = 1
	auth.Minttl = 1
	m.Ns = append(m.Ns, auth)

	w.WriteMsg(m)
	return
}

type server interface {
	ListenAndServe() error
}

func (ts *testSrv) serveTestResolver(dnsAddr string) {
	dns.HandleFunc(".", ts.dnsHandler)
	udpServer := server(&dns.Server{
		Addr:         dnsAddr,
		Net:          "udp",
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	})
	tcpServer := server(&dns.Server{
		Addr:         dnsAddr,
		Net:          "tcp",
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	})
	for _, s := range []server{udpServer, tcpServer} {
		go func(s server) {
			err := s.ListenAndServe()
			if err != nil {
				log.Fatal(err)
			}
		}(s)
	}
}

func main() {
	ts := testSrv{mu: new(sync.RWMutex), txtRecords: make(map[string][]string)}
	ts.serveTestResolver("0.0.0.0:8053")
	ts.serveTestResolver("0.0.0.0:8054")
	webServer := server(&http.Server{
		Addr: "0.0.0.0:8055",
	})
	http.HandleFunc("/set-txt", ts.setTXT)
	http.HandleFunc("/clear-txt", ts.clearTXT)
	go func(s server) {
		err := s.ListenAndServe()
		if err != nil {
			log.Fatal(err)
		}
	}(webServer)
	cmd.CatchSignals(nil, nil)
}
