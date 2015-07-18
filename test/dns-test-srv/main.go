package main

import (
	"fmt"
	"net"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
)

func dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	defer w.Close()
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	for _, q := range r.Question {
		fmt.Printf("dns-srv: Query -- [%s] %s\n", q.Name, dns.TypeToString[q.Qtype])
		if q.Qtype == dns.TypeA {
			record := new(dns.A)
			record.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
			record.A = net.ParseIP("127.0.0.1")

			m.Answer = append(m.Answer, record)
		} else if q.Qtype == dns.TypeMX {
			record := new(dns.MX)
			record.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 0}
			record.Mx = "mail." + q.Name
			record.Preference = 10

			m.Answer = append(m.Answer, record)
		}

	}

	w.WriteMsg(m)
	return
}

func serveTestResolver() {
	dns.HandleFunc(".", dnsHandler)
	server := &dns.Server{Addr: "127.0.0.1:8053", Net: "udp", ReadTimeout: time.Millisecond, WriteTimeout: time.Millisecond}
	go func() {
		err := server.ListenAndServe()
		if err != nil {
			fmt.Println(err)
			return
		}
	}()
}

func main() {
	forever := make(chan bool, 1)
	fmt.Println("dns-srv: Starting test DNS server")
	serveTestResolver()
	<-forever
}
