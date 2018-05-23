// sd-test-srv runs a simple service discovery system; it returns two hardcoded
// IP addresses for every A query.
package main

import (
	"flag"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// proxyQuery takes an A query for a domain and proxies it to Cloudflare DNS.
// This allows us to shim in sd-test-srv for our container without blocking
// lookups to github.com and coveralls.io, which are used in our `godep-restore`
// and `coverage` test phases respectively.
func proxyQuery(w dns.ResponseWriter, r *dns.Msg) {
	c := new(dns.Client)
	in, _, err := c.Exchange(r, "1.1.1.1:53")
	if err != nil {
		log.Printf("ERROR from upstream DNS: %s", err)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}
	w.WriteMsg(in)
}

func dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	if len(r.Question) != 1 {
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}
	if r.Question[0].Qtype != dns.TypeA {
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}
	if !strings.HasSuffix(r.Question[0].Name, ".boulder.") {
		proxyQuery(w, r)
		return
	}

	hdr := dns.RR_Header{
		Name:   r.Question[0].Name,
		Rrtype: dns.TypeA,
		Class:  dns.ClassINET,
		Ttl:    0,
	}

	// These two hardcoded IPs correspond to the configured addresses for boulder
	// in docker-compose.yml. In our Docker setup, boulder is present on two
	// networks, rednet and bluenet, with a different IP address on each. This
	// allows us to test load balance across gRPC backends.
	m.Answer = append(m.Answer, &dns.A{
		A:   net.ParseIP("10.77.77.77"),
		Hdr: hdr,
	}, &dns.A{
		A:   net.ParseIP("10.88.88.88"),
		Hdr: hdr,
	})

	w.WriteMsg(m)
	return
}

func main() {
	listen := flag.String("listen", ":53", "Address and port to listen on.")
	flag.Parse()
	if *listen == "" {
		flag.Usage()
		return
	}
	dns.HandleFunc(".", dnsHandler)
	go func() {
		srv := dns.Server{
			Addr:         *listen,
			Net:          "tcp",
			ReadTimeout:  time.Second,
			WriteTimeout: time.Second,
		}
		err := srv.ListenAndServe()
		if err != nil {
			log.Fatal(err)
		}
	}()
	srv := dns.Server{
		Addr:         *listen,
		Net:          "udp",
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	}
	err := srv.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
