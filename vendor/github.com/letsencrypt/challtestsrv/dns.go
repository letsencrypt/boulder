package challtestsrv

import (
	"net"

	"github.com/miekg/dns"
)

// mockSOA returns a mock DNS SOA record with fake data.
func mockSOA() *dns.SOA {
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

// dnsAnswerFunc is a function that accepts a DNS question and returns one or
// more RRs for the response.
type dnsAnswerFunc func(question dns.Question) []dns.RR

// cnameAnswers is a dnsAnswerFunc that creates CNAME RR's for the given question
// using the ChallSrv's dns mock data. If there is no mock CNAME data for the
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
// using the ChallSrv's dns mock data. If there is no mock TXT data for the
// given hostname in the question no RR's will be returned.
func (s *ChallSrv) txtAnswers(q dns.Question) []dns.RR {
	var records []dns.RR
	values := s.GetDNSOneChallenge(q.Name)
	for _, resp := range values {
		record := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
			},
			Txt: []string{resp},
		}
		records = append(records, record)
	}
	return records
}

// aAnswers is a dnsAnswerFunc that creates A RR's for the given question using
// the ChallSrv's dns mock data. If there is not a mock ipv4 A response added
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
			// If the mock data isn't a valid IPv4 address, don't use it.
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
// using the ChallSrv's dns mock data. If there is not a mock IPv6 AAAA response
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
			// If the mock data isn't a valid IPv6 address, don't use it.
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
// using the ChallSrv's dns mock data. If there is not a mock CAA response
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

// dnsHandler is a miekg/dns handler that can process a dns.Msg request and
// write a response to the provided dns.ResponseWriter. TXT, A, AAAA, CNAME,
// and CAA queries types are supported and answered using the ChallSrv's mock
// DNS data. A host that is aliased by a CNAME record will follow that alias
// one level and return the requested record types for that alias' target
func (s *ChallSrv) dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	// For each question, add answers based on the type of question
	for _, q := range r.Question {
		s.AddRequestEvent(DNSRequestEvent{
			Question: q,
		})

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

	m.Ns = append(m.Ns, mockSOA())
	_ = w.WriteMsg(m)
}
