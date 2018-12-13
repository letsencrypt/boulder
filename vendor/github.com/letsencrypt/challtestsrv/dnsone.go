package challtestsrv

import (
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
	delete(s.dnsOne, host)
}

// GetDNSOneChallenge returns a slice of TXT record values for the given host.
// If the host does not exist in the challenge response data then nil is
// returned.
func (s *ChallSrv) GetDNSOneChallenge(host string) []string {
	s.challMu.RLock()
	defer s.challMu.RUnlock()
	return s.dnsOne[host]
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
