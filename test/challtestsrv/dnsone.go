package challtestsrv

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/miekg/dns"
)

// AddDNSOneChallenge adds a TXT record for the given host with the given
// content.
func (s *ChallSrv) AddDNSOneChallenge(host, content string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	s.dnsOne[host] = append(s.dnsOne[host], content)
}

// DeleteDNSOneChallenge deletes a TXT record for the given host.
func (s *ChallSrv) DeleteDNSOneChallenge(host string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	if _, ok := s.dnsOne[host]; ok {
		delete(s.dnsOne, host)
	}
}

// GetDNSOneChallenge returns a slice of TXT record values for the given host.
// If the host does not exist in the challenge response data then nil is
// returned.
func (s *ChallSrv) GetDNSOneChallenge(host string) []string {
	s.challMu.RLock()
	defer s.challMu.RUnlock()
	return s.dnsOne[host]
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
			values := s.GetDNSOneChallenge(q.Name)
			if values == nil {
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
			addCAARecord := true

			var value string
			switch q.Name {
			case "bad-caa-reserved.com.":
				value = "sad-hacker-ca.invalid"
			case "good-caa-reserved.com.":
				value = "happy-hacker-ca.invalid"
			case "accounturi.good-caa-reserved.com.":
				uri := os.Getenv("ACCOUNT_URI")
				value = fmt.Sprintf("happy-hacker-ca.invalid; accounturi=%s", uri)
			case "recheck.good-caa-reserved.com.":
				// Allow issuance when we're running in the past
				// (under FAKECLOCK), otherwise deny issuance.
				if os.Getenv("FAKECLOCK") != "" {
					value = "happy-hacker-ca.invalid"
				} else {
					value = "sad-hacker-ca.invalid"
				}
			case "dns-01-only.good-caa-reserved.com.":
				value = "happy-hacker-ca.invalid; validationmethods=dns-01"
			case "http-01-only.good-caa-reserved.com.":
				value = "happy-hacker-ca.invalid; validationmethods=http-01"
			case "dns-01-or-http-01.good-caa-reserved.com.":
				value = "happy-hacker-ca.invalid; validationmethods=dns-01,http-01"
			default:
				addCAARecord = false
			}
			if addCAARecord {
				record := new(dns.CAA)
				record.Hdr = dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeCAA,
					Class:  dns.ClassINET,
					Ttl:    0,
				}
				record.Tag = "issue"
				record.Value = value
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

type dnsHandler func(dns.ResponseWriter, *dns.Msg)

// dnsOneServer creates an ACME DNS-01 challenge server. The provided dns
// handler will be registered with the `miekg/dns` package to
// handle DNS requests. Because the DNS server runs both a UDP and a TCP
// listener two `server` objects are returned.
func dnsOneServer(address string, handler dnsHandler) []challengeServer {
	// Register the dnsHandler
	dns.HandleFunc(".", handler)
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
	return []challengeServer{udpServer, tcpServer}
}
