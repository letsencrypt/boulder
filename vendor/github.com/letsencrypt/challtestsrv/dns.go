package challtestsrv

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// SetDefaultDNSIPv4 sets the default IPv4 address used for A query responses
// that don't match hosts added with AddDNSARecord. Use "" to disable default
// A query responses.
func (s *ChallSrv) SetDefaultDNSIPv4(addr string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	s.dnsData.defaultIPv4 = addr
}

// SetDefaultDNSIPv6 sets the default IPv6 address used for AAAA query responses
// that don't match hosts added with AddDNSAAAARecord. Use "" to disable default
// AAAA query responses.
func (s *ChallSrv) SetDefaultDNSIPv6(addr string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	s.dnsData.defaultIPv6 = addr
}

// GetDefaultDNSIPv4 gets the default IPv4 address used for A query responses
// (in string form), or an empty string if no default is being used.
func (s *ChallSrv) GetDefaultDNSIPv4() string {
	s.challMu.RLock()
	defer s.challMu.RUnlock()
	return s.dnsData.defaultIPv4
}

// GetDefaultDNSIPv6 gets the default IPv6 address used for AAAA query responses
// (in string form), or an empty string if no default is being used.
func (s *ChallSrv) GetDefaultDNSIPv6() string {
	s.challMu.RLock()
	defer s.challMu.RUnlock()
	return s.dnsData.defaultIPv6
}

// AddDNSCNAMERecord sets a CNAME record that will be used like an alias when
// querying for other DNS records for the given host.
func (s *ChallSrv) AddDNSCNAMERecord(host string, value string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	host = dns.Fqdn(host)
	value = dns.Fqdn(value)
	s.dnsData.cnameRecords[host] = value
}

// GetDNSCNAMERecord returns a target host if a CNAME is set for the querying
// host and an empty string otherwise.
func (s *ChallSrv) GetDNSCNAMERecord(host string) string {
	s.challMu.RLock()
	host = dns.Fqdn(host)
	defer s.challMu.RUnlock()
	return s.dnsData.cnameRecords[host]
}

// DeleteDNSCAMERecord deletes any CNAME alias set for the given host.
func (s *ChallSrv) DeleteDNSCNAMERecord(host string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	host = dns.Fqdn(host)
	delete(s.dnsData.cnameRecords, host)
}

// AddDNSTXTRecord adds a TXT record for the given host with the given content.
func (s *ChallSrv) AddDNSTXTRecord(host, content string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	host = dns.Fqdn(host)
	s.dnsData.txtRecords[host] = append(s.dnsData.txtRecords[host], content)
}

// GetDNSTXTRecords returns a slice of TXT record values for the given host. If
// the host does not exist in the TXT record data then nil is returned.
func (s *ChallSrv) GetDNSTXTRecords(host string) []string {
	s.challMu.RLock()
	defer s.challMu.RUnlock()
	return s.dnsData.txtRecords[dns.Fqdn(host)]
}

// DeleteDNSTXTRecord deletes all TXT records for the given host.
func (s *ChallSrv) DeleteDNSTXTRecord(host string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	delete(s.dnsData.txtRecords, dns.Fqdn(host))
}

// AddDNSARecord adds IPv4 addresses that will be returned when querying for
// A records for the given host.
func (s *ChallSrv) AddDNSARecord(host string, addresses []string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	host = dns.Fqdn(host)
	s.dnsData.aRecords[host] = append(s.dnsData.aRecords[host], addresses...)
}

// DeleteDNSARecord deletes any IPv4 addresses that will be returned when
// querying for A records for the given host.record for the given host.
func (s *ChallSrv) DeleteDNSARecord(host string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	host = dns.Fqdn(host)
	delete(s.dnsData.aRecords, host)
}

// GetDNSARecord returns a slice of IPv4 addresses (in string form) that will be
// returned when querying for A records for the given host.
func (s *ChallSrv) GetDNSARecord(host string) []string {
	s.challMu.RLock()
	host = dns.Fqdn(host)
	defer s.challMu.RUnlock()
	return s.dnsData.aRecords[host]
}

// AddDNSAAAARecord adds IPv6 addresses that will be returned when querying for
// AAAA records for the given host.
func (s *ChallSrv) AddDNSAAAARecord(host string, addresses []string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	host = dns.Fqdn(host)
	s.dnsData.aaaaRecords[host] = append(s.dnsData.aaaaRecords[host], addresses...)
}

// DeleteDNSAAAARecord deletes any IPv6 addresses that will be returned when
// querying for A records for the given host.
func (s *ChallSrv) DeleteDNSAAAARecord(host string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	host = dns.Fqdn(host)
	delete(s.dnsData.aaaaRecords, host)
}

// GetDNSAAAARecord returns a slice of IPv6 addresses (in string form) that will
// be returned when querying for A records for the given host.
func (s *ChallSrv) GetDNSAAAARecord(host string) []string {
	s.challMu.RLock()
	defer s.challMu.RUnlock()
	host = dns.Fqdn(host)
	return s.dnsData.aaaaRecords[host]
}

// CAAPolicy holds a tag and a value for a CAA policy record. See
// https://tools.ietf.org/html/rfc6844
type CAAPolicy struct {
	Tag   string
	Value string
}

// AddDNSCAARecord adds CAA records that will be returned when querying
// CAA for the given host.
func (s *ChallSrv) AddDNSCAARecord(host string, policies []CAAPolicy) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	host = dns.Fqdn(host)
	s.dnsData.caaRecords[host] = append(s.dnsData.caaRecords[host], policies...)
}

// DeleteDNSCAARecord deletes any CAA policies that will be returned when
// querying CAA for the given host.
func (s *ChallSrv) DeleteDNSCAARecord(host string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	host = dns.Fqdn(host)
	delete(s.dnsData.caaRecords, host)
}

// GetDNSCAARecord returns a slice of CAA policy records that will
// be returned when querying CAA for the given host.
func (s *ChallSrv) GetDNSCAARecord(host string) []CAAPolicy {
	s.challMu.RLock()
	defer s.challMu.RUnlock()
	host = dns.Fqdn(host)
	return s.dnsData.caaRecords[host]
}

// AddDNSServFailRecord configures the chall srv to return SERVFAIL responses
// for all queries for the given host.
func (s *ChallSrv) AddDNSServFailRecord(host string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	host = dns.Fqdn(host)
	s.dnsData.servFailRecords[host] = true
}

// DeleteDNSServFailRecord configures the chall srv to no longer return SERVFAIL
// responses for all queries for the given host.
func (s *ChallSrv) DeleteDNSServFailRecord(host string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	host = dns.Fqdn(host)
	delete(s.dnsData.servFailRecords, host)
}

// GetDNSServFailRecord returns true when the chall srv has been configured with
// AddDNSServFailRecord to return SERVFAIL for all queries to the given host.
func (s *ChallSrv) GetDNSServFailRecord(host string) bool {
	s.challMu.RLock()
	defer s.challMu.RUnlock()
	host = dns.Fqdn(host)
	return s.dnsData.servFailRecords[host]
}

// dnsAnswerFunc is a function that accepts a DNS question and returns one or
// more RRs for the response.
type dnsAnswerFunc func(question dns.Question) []dns.RR

// cnameAnswers is a dnsAnswerFunc that creates CNAME RR's for the given question
// using the ChallSrv's DNS records. If there is no CNAME record for the
// given hostname in the question no RR's will be returned.
func (s *ChallSrv) cnameAnswers(q dns.Question) []dns.RR {
	var records []dns.RR

	if value := s.GetDNSCNAMERecord(q.Name); value != "" {
		record := &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
			},
			Target: value,
		}

		records = append(records, record)
	}

	return records
}

// txtAnswers is a dnsAnswerFunc that creates TXT RR's for the given question
// using the ChallSrv's DNS records. If there is no TXT record for the
// given hostname in the question no RR's will be returned.
func (s *ChallSrv) txtAnswers(q dns.Question) []dns.RR {
	var records []dns.RR
	values := s.GetDNSTXTRecords(q.Name)
	for _, resp := range values {
		record := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
			},
			Txt: splitTXTRecordValue(resp),
		}
		records = append(records, record)
	}
	return records
}

// splitTXTRecordValue splits a TXT value into RFC 1035 <character-string>
// chunks of at most 255 octets so long TXT values can be represented as
// multiple strings in one RR.
func splitTXTRecordValue(value string) []string {
	const maxTXTStringOctets = 255
	if len(value) <= maxTXTStringOctets {
		return []string{value}
	}

	var chunks []string
	for len(value) > maxTXTStringOctets {
		chunks = append(chunks, value[:maxTXTStringOctets])
		value = value[maxTXTStringOctets:]
	}
	if len(value) > 0 {
		chunks = append(chunks, value)
	}
	return chunks
}

// aAnswers is a dnsAnswerFunc that creates A RR's for the given question using
// the ChallSrv's DNS records. If there is not a IPv4 A record added
// for the given hostname in the question the default IPv4 address will be used
// for the response.
func (s *ChallSrv) aAnswers(q dns.Question) []dns.RR {
	var records []dns.RR
	// Don't answer any questions for IP addresses with a fakeDNS response.
	// These queries are invalid!
	if ip := net.ParseIP(q.Name); ip != nil {
		return records
	}
	values := s.GetDNSARecord(q.Name)
	if defaultIPv4 := s.GetDefaultDNSIPv4(); len(values) == 0 && defaultIPv4 != "" {
		values = []string{defaultIPv4}
	}
	for _, resp := range values {
		ipAddr := net.ParseIP(resp)
		if ipAddr == nil || ipAddr.To4() == nil {
			// If the DNS records aren't a valid IPv4 address, don't use them.
			continue
		}
		record := &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
			},
			A: ipAddr,
		}
		records = append(records, record)
	}
	return records
}

// aaaaAnswers is a dnsAnswerFunc that creates AAAA RR's for the given question
// using the ChallSrv's DNS records. If there is not an IPv6 AAAA record
// added for the given hostname in the question the default IPv6 address will be
// used for the response.
func (s *ChallSrv) aaaaAnswers(q dns.Question) []dns.RR {
	var records []dns.RR
	values := s.GetDNSAAAARecord(q.Name)
	if defaultIPv6 := s.GetDefaultDNSIPv6(); len(values) == 0 && defaultIPv6 != "" {
		values = []string{defaultIPv6}
	}
	for _, resp := range values {
		ipAddr := net.ParseIP(resp)
		if ipAddr == nil || ipAddr.To4() != nil {
			// If the DNS records aren't a valid IPv6 address, don't use them.
			continue
		}
		record := &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
			},
			AAAA: ipAddr,
		}
		records = append(records, record)
	}
	return records
}

// caaAnswers is a dnsAnswerFunc that creates CAA RR's for the given question
// using the ChallSrv's DNS records. If there is not a CAA record
// added for the given hostname in the question no RRs will be returned.
func (s *ChallSrv) caaAnswers(q dns.Question) []dns.RR {
	var records []dns.RR
	values := s.GetDNSCAARecord(q.Name)
	for _, resp := range values {
		record := &dns.CAA{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeCAA,
				Class:  dns.ClassINET,
			},
			Tag:   resp.Tag,
			Value: resp.Value,
		}
		records = append(records, record)
	}
	return records
}

type writeMsg interface {
	WriteMsg(m *dns.Msg) error
}

type dnsToHTTPWriter struct {
	http.ResponseWriter
}

func (d *dnsToHTTPWriter) WriteMsg(m *dns.Msg) error {
	d.Header().Set("Content-Type", "application/dns-message")
	d.WriteHeader(http.StatusOK)
	b, err := m.Pack()
	if err != nil {
		return err
	}
	_, err = d.Write(b)
	return err
}

// dohHandler handles a DoH request by POST only.
func (s *ChallSrv) dohHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	msg := new(dns.Msg)
	err = msg.Unpack(body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, err)
		return
	}

	s.dnsHandlerInner(&dnsToHTTPWriter{w}, msg, r.Header.Get("User-Agent"))
}

// dnsHandler is a miekg/dns handler that can process a dns.Msg request and
// write a response to the provided dns.ResponseWriter. TXT, A, AAAA, CNAME,
// and CAA queries types are supported and answered using the ChallSrv's DNS
// records. A host that is aliased by a CNAME record will follow that alias
// one level and return the requested record types for that alias' target
func (s *ChallSrv) dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	s.dnsHandlerInner(w, r, "")
}

// newDefaultSOA returns a DNS SOA record with sensible default values.
func newDefaultSOA() *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   "challtestsrv.invalid.",
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
		},
		Ns:      "ns.challtestsrv.invalid.",
		Mbox:    "master.challtestsrv.invalid.",
		Serial:  1,
		Refresh: 1,
		Retry:   1,
		Expire:  1,
		Minttl:  1,
	}
}

func (s *ChallSrv) dnsHandlerInner(w writeMsg, r *dns.Msg, userAgent string) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	// For each question, add answers based on the type of question
	for _, q := range r.Question {
		s.AddRequestEvent(DNSRequestEvent{
			Question:  q,
			UserAgent: userAgent,
		})

		// If there is a ServFail record set then ignore the question and set the
		// SERVFAIL rcode and continue.
		if s.GetDNSServFailRecord(q.Name) {
			m.SetRcode(r, dns.RcodeServerFailure)
			continue
		}

		// If a CNAME exists for the question include the CNAME record and modify
		// the question to instead lookup based on that CNAME's target
		if cname := s.GetDNSCNAMERecord(q.Name); cname != "" {
			cnameRecords := s.cnameAnswers(q)
			m.Answer = append(m.Answer, cnameRecords...)

			q = dns.Question{Name: cname, Qtype: q.Qtype}
		}

		var answerFunc dnsAnswerFunc
		switch q.Qtype {
		case dns.TypeCNAME:
			answerFunc = s.cnameAnswers
		case dns.TypeTXT:
			answerFunc = s.txtAnswers
		case dns.TypeA:
			answerFunc = s.aAnswers
		case dns.TypeAAAA:
			answerFunc = s.aaaaAnswers
		case dns.TypeCAA:
			answerFunc = s.caaAnswers
		default:
			m.SetRcode(r, dns.RcodeNotImplemented)
		}

		if answerFunc == nil {
			break
		}

		if records := answerFunc(q); len(records) > 0 {
			m.Answer = append(m.Answer, records...)
		}
	}

	m.Ns = append(m.Ns, newDefaultSOA())
	_ = w.WriteMsg(m)
}

type dnsHandler func(dns.ResponseWriter, *dns.Msg)

// dnsServer creates a DNS server that registers the provided handler with the
// `miekg/dns` package. Because the DNS server runs both a UDP and a TCP
// listener, two `server` objects are returned.
func dnsServer(address string, handler dnsHandler) []challengeServer {
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

type doh struct {
	*http.Server
	tlsCert, tlsCertKey string
}

func (s *doh) Shutdown() error {
	return s.Server.Shutdown(context.Background())
}

func (s *doh) ListenAndServe() error {
	return s.ListenAndServeTLS(s.tlsCert, s.tlsCertKey)
}

// dohServer creates a DNS-over-HTTPS server backed by the provided handler.
func dohServer(address string, tlsCert, tlsCertKey string, handler http.Handler) *doh {
	return &doh{
		&http.Server{
			Handler:      handler,
			Addr:         address,
			ReadTimeout:  time.Second,
			WriteTimeout: time.Second,
		},
		tlsCert,
		tlsCertKey,
	}
}
