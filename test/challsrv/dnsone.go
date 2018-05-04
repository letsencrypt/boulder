package challsrv

import (
	"net"
	"os"
	"time"

	"github.com/miekg/dns"
)

// AddDNSOneChallenge adds a TXT record for the given host with the given
// content.
func (s *ChallSrv) AddDNSOneChallenge(host, content string) {
	s.dnsMu.Lock()
	defer s.dnsMu.Unlock()
	s.dnsOne[host] = append(s.dnsOne[host], content)
}

// DeleteDNSOneChallenge deletes a TXT record for the given host.
func (s *ChallSrv) DeleteDNSOneChallenge(host string) {
	s.dnsMu.Lock()
	defer s.dnsMu.Unlock()
	if _, ok := s.dnsOne[host]; ok {
		delete(s.dnsOne, host)
	}
}

// GetDNSOneChallenge returns a slice of TXT record valuefor the given host and
// a true bool. If the host does not exist in the challenge response data then
// an empty slice is returned and a false bool.
func (s *ChallSrv) GetDNSOneChallenge(host string) ([]string, bool) {
	s.dnsMu.RLock()
	defer s.dnsMu.RUnlock()
	content, present := s.dnsOne[host]
	return content, present
}

// dnsHandler is a miekg/dns handler that can process a dns.Msg request and
// write a response to the provided dns.ResponseWriter.
func (s *ChallSrv) dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
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
		s.log.Printf("Query -- [%s] %s\n", q.Name, dns.TypeToString[q.Qtype])
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
			values, present := s.GetDNSOneChallenge(q.Name)
			if !present {
				continue
			}
			s.log.Printf("Returning %d TXT records: %#v\n", len(values), values)
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

// dnsOneServer creates and starts an ACME DNS-01 challenge server. The
// server's dns handler will be registered with the `miekg/dns` package to
// handle DNS requests. A cleanup function is returned to the caller that should
// be used to request the clean shutdown of the HTTP server.
func (srv *ChallSrv) dnsOneServer(address string) func() {
	srv.log.Printf("Starting TCP and UDP DNS-01 challenge server on %s\n", address)
	// Register the dnsHandler
	dns.HandleFunc(".", srv.dnsHandler)
	// Create a UDP DNS server
	udpServer := &dns.Server{
		Addr:         address,
		Net:          "udp",
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	}
	// Create a TCP DNS server
	tcpServer := &dns.Server{
		Addr:         address,
		Net:          "tcp",
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	}
	// Start both servers in their own dedicated Go routines
	for _, s := range []*dns.Server{udpServer, tcpServer} {
		go func(s *dns.Server) {
			err := s.ListenAndServe()
			if err != nil {
				srv.log.Print(err)
			}
		}(s)
	}
	// Return a cleanup function that shuts down both DNS servers.
	return func() {
		srv.log.Printf("Shutting down DNS-01 servers on %s", address)
		for _, s := range []*dns.Server{udpServer, tcpServer} {
			if err := s.Shutdown(); err != nil {
				srv.log.Printf("Err shutting down DNS-01 server on %s: %s", address, err)
			}
		}
	}
}
